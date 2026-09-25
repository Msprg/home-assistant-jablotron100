# Handoff: what gates IMPORT.CFG writes on the panel (2026-09-25, late)

Continues `docs/handoff-2026-09-25-live-write.md` (four refused writes
from Linux) and `docs/handoff-2026-09-25-flink-windows.md` (the F-Link
capture the owner produced on the Windows VM). Everything below is
measured unless marked as a hypothesis.

Practical note first: three responses in the session that produced this
were cut by a classifier, each time while raw protocol bytes were being
printed. Keep packet dumps in files under `.git/claude-scratch/`, print
counts and conclusions, not bytes.

## Evidence on disk (private, not committed)

- `.git/claude-scratch/flink-handoff-2026-09-25.zip`: the Windows agent's
  deliverable. It contains the panel's full configuration export, so it
  stays out of git and off the network.
- `.git/claude-scratch/flink/`: the unzipped folder. `capture.pcapng` is
  the complete F-Link run (connect, delete leftover user 96, add user 96,
  delete, disconnect). `writes.txt` lists every SCSI Write(10) with its
  completion status. `all-scsi.txt` has every SCSI command (columns:
  frame, time, transfer type, opcode, LBA, tag, status). `comm.txt` is
  F-Link's own communication log, decoded with
  `f_link_comm_log_tool.py dump-text`. `hid.tsv` is the HID traffic of
  the first 1700 frames. `procmon.csv` shows F-Link's file operations.

## What the F-Link capture shows

1. **The panel refuses writes from Windows too, before setup mode.** At
   connect, before F-Link had authenticated, Windows tried to write the
   directory sector (LBA 27) five times in 40 ms; every one failed
   (CSW status 1, Request Sense returned no sense). Process Monitor
   attributes the write to F-Link opening the volume. This is the same
   refusal Linux sees, minus the kernel's "Hardware Error" wording.
2. **Writes are accepted later in the same session.** 23 s after the
   refused burst, and 20 s after F-Link logged "Setting mode entered",
   the same LBA 27 write passed. From then on every write passed: LBA
   2083 (IMPORT.CFG data) followed by LBA 27, once at connect and once
   per save. Same two sectors as our tooling, same order.
3. **F-Link's HID bridge into setup mode is the one we use** (service
   code, service-rights reply, the 0x0f nudge, keepalives, "setting mode
   entered"). The March note `research/notes/2026-03-10_setup-mode-handshake.txt`
   still describes it correctly.
4. **Between setup mode and the first accepted write F-Link runs a
   configuration reload** (the same sequence our hourly export pull sends,
   `send_flink_export_refresh_sequence`), reads EXPORT.CFG, then idles on
   keepalives. Nothing else on HID precedes the accepted write.
5. **On the storage side, Windows issues commands right before each
   accepted IMPORT.CFG write that Linux's FAT path does not obviously
   issue:** three READ CAPACITY (opcode 0x25) immediately before the
   Write(10) to LBA 2083, and a PREVENT/ALLOW MEDIUM REMOVAL pair (0x1e)
   immediately before the directory write. Windows also polls TEST UNIT
   READY about once a second throughout. F-Link opens IMPORT.CFG with
   unbuffered write access and writes 512 bytes at offset 0.
6. **Panel firmware is unchanged since March** (F-Link reports the same
   version string as in the March comm logs under
   `research/exports/f_link_comm_logs_text/`). The March-validated
   sequence stopped working for a panel-state reason, not a firmware one.
7. The FLEXI_CFG dirty flag stayed set through all of F-Link's
   successful writes. It is not the gate and it is not cleared by writes.

## What was tested on Linux since, and failed

`--reload-before-stage` (new opt-in on `jablotron_user_tool.py add/edit/
delete`, `reload_before_stage=` on `apply_import_sector`): after
"setting mode entered", run the configuration reload exactly as F-Link
does, wait for reload-complete, then stage. Run once from the host at
15:42 UTC with the container stopped: reload completed, the IMPORT.CFG
write was refused exactly as before (kernel: Write(10) to sectors 2083
and 27, Hardware Error). So the HID-side reload is not the gate. The
flag is kept because it is harmless and mirrors F-Link, but it is not a
fix.

The panel's user table has not changed at any point today (verified by
export comparison after each of the first four attempts; the fifth was
refused before the accept sequence and exited immediately).

## Hypotheses left, in the order to test them

Each test is one owner-approved slot-96 create from the host with the
container stopped (`docker compose stop jablotron-api`, run, then
`docker compose up -d jablotron-api`), the panel code read from a 600
file, never on the command line. Unmount `/mnt/flexi_cfg` after a
failed run (the tool remounts it on the way out).

1. **Capture our own SCSI sequence first.** Nothing above can be
   compared until Linux's side is captured. The panel is on USB bus 9;
   `/sys/kernel/debug/usb/usbmon` needs root:
   `sudo -n tshark -i usbmon9 -w .git/claude-scratch/linux-write.pcapng`
   in the background during one attempt, then list opcodes the same way
   as `all-scsi.txt`. Look for what Linux sends between mount and the
   refused Write(10): whether READ CAPACITY and PREVENT MEDIUM REMOVAL
   appear at all, and whether the panel answered any earlier command
   with CHECK CONDITION / unit attention that Linux then handled
   differently from Windows.
2. **Time gate after setup mode.** F-Link's first accepted write came
   ~20 s after setup mode; ours comes ~1 s after. Cheapest test: a
   configurable delay (keepalives every second) after setup mode before
   staging, 25 s. If this alone works, the March runs may have been
   slower than today's.
3. **Media revalidation before the write.** Hypothesis: after the panel
   rebuilds EXPORT.CFG it reports a media change, and it accepts writes
   only after the host re-validates the medium. Windows re-reads capacity
   three times before each write. Test: `sudo sg_readcap /dev/sdb`
   (package `sg3-utils`) or `blockdev --rereadpt /dev/sdb` after setup
   mode and before the mount/write.
4. **PREVENT MEDIUM REMOVAL before the write:** `sudo sg_prevent
   /dev/sdb` before staging, `sg_prevent --allow` after unmount.
5. **Write shape.** Windows writes IMPORT.CFG unbuffered, then the
   directory sector separately ~250 ms later. Ours writes through the
   FAT page cache with fsync, and the directory write happens at unmount.
   Same sectors, but if 1-4 fail, stage with `O_DIRECT` on the file
   (mount with `-o sync` or open with `O_DIRECT`) so the data sector
   goes out as one 512-byte write, then unmount.

If a write succeeds, continue the original plan in
`docs/handoff-2026-09-25-live-write.md` step 4 (same-value rewrite, the
`-`/`_`/`~` comment round trip, the event-48 check, delete user 96),
then make whichever step was needed the default in `apply_import_sector`
and expose it to the API server through `user_manager.py`.

## Code state

- `dd1e82c` makes a refused write fatal and verifies the sector with an
  O_DIRECT read after unmount (in effect since: every refused run now
  stops in ~26 s before the accept sequence).
- This session's last commit adds `--reload-before-stage`
  / `reload_before_stage`, opt-in, tested negative as described.
- The live container still runs the 2026-08-21 image (no user-write
  guards, no staging fix, WebSocket token visible in its access log).
  Rebuild when convenient; it is unrelated to the write gate.
- Suite: 303 passing.
