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

## Resolution (same evening, 16:04-16:27 UTC)

Writes work from Linux again. The full owner-approved cycle ran from the
host with the container stopped (each step one `jablotron_user_tool.py`
invocation, usbmon on bus 9 recording, container restarted with `up -d`
afterwards):

| UTC | Step | Result |
| --- | --- | --- |
| 16:04 | `add 96` (plan step 1, capture) | Panel **accepted** both `Write(10)`s (no kernel error, IMPORT.CFG directory mtime updated); the tool's own read-back verify failed, accept sequence not run. tshark had failed to open its output file, so no capture. |
| 16:18 | `add 96`, verify fixed (`c7649ce`) | Accepted, read-back matched, accept sequence ran, authoritative refetch shows user 96 (92 raw users). Event 48 at 18:18:29 panel time, then 157, 156. |
| 16:21 | `edit 96 --comment <same value>` | `requested_unchanged comment`; the panel still logs a 48. |
| 16:22 | `edit 96 --comment rt-a_b~c` | Reads back exactly (`-`, `_`, `~` survive the round trip). 48 logged. |
| 16:25 | `jablotron_event_tool.py recent` | Only 119/150/48/157/156/123 today; no alarm or tamper events from the test. |
| 16:25 | `delete 96` | "user 96 absent after delete", 91 raw users; the decoded table is identical to the 16:04 pre-add export, line for line. |

Two separate facts explain the day:

1. **The refusals were real and stopped on their own.** Every attempt from
   13:31 to 15:42 UTC got sense *Hardware Error* on the same two sectors;
   from 16:04 UTC on the panel accepted the same sequence, unchanged
   (no reload, no delay, no `sg_*` command, filesystem staging). The usbmon
   capture of the accepted 16:18 write shows Linux sending no READ CAPACITY
   at all and only the kernel's PREVENT/ALLOW pair at mount and unmount:
   `Write(10)` LBA 2083, `Write(10)` LBA 27 four milliseconds later, LBA 27
   again 1.8 s later at unmount, all CSW status 0. So hypotheses 2-5 above
   (time gate, revalidation, prevent-removal, write shape) are not what the
   panel wants; whatever gated it between 13:31 and 15:42 was panel state
   that cleared by itself. The F-Link capture's "refused at connect,
   accepted 20 s later" fits the same picture. If it happens again: wait
   and retry, do not change the sequence.
2. **The read-back verify read the wrong sector.** `IMPORT_START_LBA`
   (2083, from `flexi_pcap_tool`) is an absolute disk LBA; the device the
   tooling opens is the partition `/dev/sdb1`, which starts at absolute
   sector 1 (`/sys/class/block/sdb1/start`). Applied to the partition, 2083
   is absolute 2084, IMPORT.CFG+512, which nobody writes. So the O_DIRECT
   verify added in `dd1e82c` could never pass, and `stage_import_direct`
   (debug mode) wrote the wrong sector (the 13:31 kernel log says
   `sector 2084`). The export read was never affected: it walks the FAT.
   `resolve_import_sector_lba` now does the same walk for IMPORT.CFG
   (fallback: constant minus partition start). This is also why the March
   note says the probe "sometimes matched": it was reading a zero sector.

Evidence (private, contains the config export): `.git/claude-scratch/usbmon/`
holds `linux-cap2.pcapng` (the accepted add), `linux-batch1.pcapng` (both
edits), `linux-batch2.pcapng` (event pull and delete), the tool logs, and
`events-batch2.jsonl`. Decode the usbmon files with
`tshark -o usb.try_heuristics:TRUE -Y usbms -T fields -e scsi_sbc.opcode -e scsi_sbc.rdwr10.lba -e usbms.dCSWStatus`
(the `-d usb.bulk==8,...` form does not work on usbmon captures).

Still open:

- The live container runs the 2026-08-21 image. It needs a rebuild to get
  `c7649ce`, `dd1e82c` and the user-write guards; until then API writes
  will fail at the read-back verify in the same way the 16:04 run did, or
  worse, run the accept sequence against unverified storage (the old
  image predates `dd1e82c`). Rebuild deliberately, not as a dropout fix.
- `--reload-before-stage` stays opt-in; it was not needed.
- The FAT dirty flag on FLEXI_CFG is still set (every mount logs "Volume
  was not properly unmounted"); Windows saw the same. Harmless so far.
- The old image logs a pre-existing crash in device-info parsing
  (`binary_to_int` on an empty string from
  `_parse_device_battery_level_packet`); unrelated to writes.
- `tests/test_fat_volume_reader.py::test_the_server_event_path_never_mounts`
  talks to the real panel when one is attached: it failed with "System is
  already in configuration mode" while a live session was open, and passes
  alone. It should be hermetic.

## Correction (16:48-17:05 UTC): the gate follows the login code, not the clock

The "stopped on their own" reading above is probably wrong. After the
container was rebuilt (`777e43d`, then `43fa279`), writes through the
running container were tried against the host tool, minutes apart:

| UTC | Path | Login code | Result |
| --- | --- | --- | --- |
| 16:48 | API `POST /v1/users` (container) | container's configured code | Refused (*Hardware Error* on sectors 2083 and 27); the old image's `SystemExit` stopped uvicorn and Docker restarted the container |
| 16:56 | API `POST /v1/users` (container, `43fa279`) | container's code | Refused; HTTP 409, no restart |
| 16:56 | host `add 96`, container stopped | tool default (the service code, per `research/notes/2026-03-10_setup-mode-handshake.txt`) | Accepted, user 96 created, event 48 |
| 16:59 | API `PATCH /v1/users/96` (container), usbmon recording | container's code | Refused; 409, no restart |
| 17:02 | host `delete 96` | tool default | Write accepted and verified, 48 logged, but user 96 still present (see below) |
| 17:04 | host `delete 96` again | tool default | Absent; table identical to the pre-add baseline |

- **The container has what filesystem staging needs.** `CAP_SYS_ADMIN`,
  AppArmor unconfined, root, `mount` present; the mount succeeds and the
  Write(10) reaches the panel. `direct` mode is not the answer: raw sector
  writes never trigger an import (March transport review).
- **The two paths differ in one input.** The usbmon captures of the
  accepted host write (`linux-host3.pcapng`) and the refused container
  write (`linux-ctr1.pcapng`) match in HID timing (same bursts, same last
  three commands 3.5, 1.2 and 0.6 s before the write) and in the SCSI
  commands before the write. The container logs in with its configured
  code, which is not the tool's default service code (compared for
  equality only, neither value printed). With the container's code the
  panel still reaches setup mode, and staging runs. But it answers the
  storage write with an immediate CHECK CONDITION.
- **This fits the whole day** if the morning host runs used the container's
  code: the earlier handoff says the host runs read the code from a private
  file. That was not re-checked (reading it was out of bounds for this
  session), so it is the one unconfirmed link. The F-Link capture fits too:
  refused before F-Link authenticated as service, accepted after.
- **Proof still owed:** one API write with the container logging in with the
  service code. That is an owner decision (which code the API holds), see
  below.
- **The 17:02 delete that did not apply:** our import was accepted at
  19:02:25 local, while a cloud "Server" channel session was open (156 at
  19:02:20, 157 at 19:02:43). The panel logged 48, but the delete did not
  persist; the retry two minutes later did. Likely the cloud session wrote
  its own configuration back. The tool still exited 0 while printing user 96
  as present after a delete, which it should treat as a failure.

Options for the owner, not done here:

1. Point `JABLOTRON_PANEL_AUTH_CODE` at the service code. Simplest; the API
   then holds the service code for every operation, including arming.
2. Add a separate write-only code (for example
   `JABLOTRON_PANEL_WRITE_AUTH_CODE`) used only by `apply_import_sector`.
   Keeps arming and polling on the current code.

Until one of those is in place, every user write through the API will be
refused with 409, not a coin toss.

## Confirmed (owner's second F-Link capture, 20:19-20:33 local)

The owner ran the same F-Link create and delete of a test user in slot 96
twice: once logged in with the service code, once with the code the
container uses. Evidence (private, contains both codes and the config
export): `.git/claude-scratch/flink-logincode/`, with the original zip beside it.

| | Service code | Container's code |
| --- | --- | --- |
| Write(10) to FLEXI_CFG | 10 (connect burst, then LBA 2083 + 27 per save) | 0 |
| F-Link opens IMPORT.CFG | yes, 512 bytes at offset 0 per save | never, only reads EXPORT.CFG |
| Host-to-panel HID SET_REPORTs | 312, flat keepalive rate | 572, bursts of 118 (save) and 128 (delete) |
| Panel applied the change | yes | yes |

So the login code selects the write path. With the service code the panel
takes configuration through IMPORT.CFG after setup mode. With the
container's code it refuses storage writes, and F-Link instead sends the
change over HID. That is why every API write was refused. The container
logs in with the second code and uses the storage path. The HID
path is a separate protocol the tooling does not implement yet.

What a first look at the HID save burst shows (script:
`.git/claude-scratch/flink-logincode/compare.py`, statistics only):

- The user's name and comment are in the burst as plain ASCII.
- None of the IMPORT.CFG sector's content appears in it (0 of 61 8-byte
  windows), so the HID record format differs from the IMPORT sector
  encoding; `build_upsert_sector` does not carry over as is.
- The 118 save reports use seven distinct 2-byte heads; one head accounts
  for 78 of them. The dumps are 64-byte payloads (the capture agent's
  "72 bytes" counts the setup packet).
- F-Link's comm log has no command names for these messages.

Choices, in order of cost:

1. **Write-only service code for the storage path.** Works with today's
   tooling (host runs with the service code succeeded all evening). A
   `JABLOTRON_PANEL_WRITE_AUTH_CODE` passthrough is already in the working
   tree, uncommitted, not written in this session. Cost: the API holds the
   service code.
2. **Implement the HID configuration write.** No mount, no
   `CAP_SYS_ADMIN`, no dependence on the FAT volume, and no service code in
   the API. Cost: a new reverse-engineering project, the record format and
   the handshake around the burst. The two captures give one save and one
   delete of a known record, which is a good start but not enough to
   generalise to every field.

## Decoded (2026-10-03): one msgpack command, two transports

A second pass over the same two captures, this time with a merged
host-and-panel HID timeline (`hid_flow_tool.py`, added for this) and
F-Link's own comm logs beside it. This corrects the "different record
format" reading in "Confirmed" above.

### The login rights select the path, not the code as such

- F-Link's comm log for session A says `Code accepted with ARC rights`,
  `LoggedPosition: 7`. For session B it says `Code accepted with master
  rights`, `LoggedPosition: 100`. The March 2026 comm logs for the same
  position-7 code say `Code accepted with service rights`, so that user's
  authority was changed from Service to ARC between March and September.
  The tooling and the status log still call it "the service code"; the
  panel no longer does.
- The panel states this in its login reply `80 1A 0C <25 bytes>`, which
  every accepted login gets (not only service logins, as the March note
  assumed). Byte 8 is `0x28 + rights` (`0x28` master, `0x29` service,
  `0x2A` ARC); byte 10 is the logged position (`0x07`, `0x64`). Bytes 0-3
  look like a section mask (`FF FF 0F 00` now, `FF FF 00 00` in March);
  `3F 00 3F 00` at bytes 4-7 and `27` at byte 12 were constant across all
  captures. The rest is zero.

### Both transports carry the same bytes

- **Storage transport (ARC and service rights).** F-Link talker
  `JA107_IMPORT_CFG`: SCSI Write(10) of the IMPORT.CFG sector (LBA 2083,
  msgpack XOR `0xFF` on the medium, `C1 C1 C1 C1` trailer) and the
  directory sector (LBA 27), then `52 01 24`. The panel answers
  `52 04 83 0B 24 <progress>` from `00` to `64` and finishes with
  `52 04 83 01 24 01`.
- **HID transport (master rights).** F-Link talker `JA100_WRITE_CFG`: one
  SET_REPORT carrying TLV type `0x1D`: `1D <len> 09 00 <msgpack>`. The
  panel answers `1D 03 44 00 00`. The save was
  `1D 3B 09 00 81 07 81 60 8C 00 00 01 00 02 00 03 94 00 00 00 00 04 A6
  "Test96" 05 A0 06 A0 07 92 81 00 A0 81 00 A0 08 00 09 00 0A AC
  "handoff-test" 0B FF`, which msgpack-decodes to
  `9, 0, {7: {96: {0: 0, 1: 0, 2: 0, 3: [0, 0, 0, 0], 4: "Test96", 5: "",
  6: "", 7: [{0: ""}, {0: ""}], 8: 0, 9: 0, 10: "handoff-test", 11: -1}}}`.
  The delete was `1D 07 09 00 81 07 81 60 C0` = `9, 0, {7: {96: nil}}`.
- The msgpack after the `09 00` prefix is byte-identical to the XOR-decoded
  IMPORT.CFG sector body of session A, for the save and for the delete. It
  is the same command on a different transport. The "0 of 61 windows"
  comparison in "Confirmed" failed only because it compared against the
  XOR-encoded sector. `import_cfg_tool.py build-user-upsert` and
  `build-user-delete` already produce exactly this payload.
- The 118- and 128-report "bursts" were almost entirely F-Link's periphery
  diagnostics loop (`94 02 nn 01` / `96 03 nn 09 00` / `52 02 28 nn` and
  the `90` / `52 A8` replies), which runs while the Devices tab is open.
  The write itself is one report each way.
- The commit after either transport is the same: `52 01 0C`
  (`JA100_ACCEPT_CFG`) answered by `52 03 83 01 02`; `80 01 14` answered
  by `80 01 17`; `80 01 0F` answered by `80 02 1A 0A`; `80 01 12`;
  `52 03 1A 01 00` answered by `52 07 1B 01 00 ...`. Both sessions were in
  configuration mode after login (0x51 trailer `0x94`), and both wrote
  from that state.

### Still unknown

- The `09 00` prefix in front of the msgpack: constant in both writes;
  object class, sequence number or pass index are all plausible.
- The reply `44 00 00`: identical for save and delete; there is no failure
  sample yet, so the error shape is unknown.
- Whether `1D` accepts other configuration roots (`{5: ...}` for
  communications, as the storage path does) and whether a service- or
  ARC-rights session may also use `1D`. The captures only show master
  rights using it and ARC rights using storage.

### Implemented (2026-10-03, same day)

- `jablotron_re_tools.py`: `parse_login_rights` (from `80 1A 0C`),
  `enter_setup_mode` returns them; `read_config_revision` /
  `verify_config_revision_advanced` (`52 03 1A 01 00`); the import-accept
  sequence is now reply-driven (`52 01 24` waits for `52 04 83 01 24 01`
  with progress extending the wait, `52 01 0C` requires `52 03 83 01 02`,
  then `80 01 14` awaits `80 01 17`); `write_config_over_hid` /
  `apply_config_payload_over_hid` (the `0x1D` transport);
  `probe_login_rights`; `apply_sector(transport=...)`. A storage write from a
  master-rights login now fails before the volume is touched, with a
  message naming the transport setting.
- API: `JABLOTRON_PANEL_WRITE_TRANSPORT=auto|hid|storage` (PanelSettings,
  PanelRuntimeConfig, UserManagerConfig). `auto` logs in once before each
  write to read the rights and uses `hid` for master, `storage` for
  service/ARC. CLI: `jablotron_user_tool.py add|edit|delete --write-transport`.
- Tests: `tests/test_hid_config_write.py` rebuilds the captured save and
  delete packets byte for byte from the sector builders and scripts the
  captured replies through the whole session.
- Not yet live-tested: the API container was still running the previous
  image with the panel attached when this was written.

### What this changes for the API

Choice 2 above is no longer a reverse-engineering project. A user write
over HID is: log in with a master-rights code, reach configuration mode
as the storage path already does, send `1D` + `09 00` + the
`import_cfg_tool` payload, wait for `1D 03 44 00 00`, run the existing
commit sequence, verify with a fresh export. No FAT mount, no block
device, no `CAP_SYS_ADMIN`, and no second code in the API. The first live
test should be the same slot-96 create and delete with the container's own
code, raw over HID, with a fresh export before and after.

Reproduce the decode offline (the capture folder stays private):

```bash
python3 hid_flow_tool.py .git/claude-scratch/flink-logincode/capture-code9146.pcapng -o /tmp/flow-9146.txt --histogram
grep -n '1d:' /tmp/flow-9146.txt
python3 -c "import msgpack;u=msgpack.Unpacker(strict_map_key=False);u.feed(bytes.fromhex('0900810781608c00000100020003940000000004a654657374393605a006a007928100a08100a0080009000aac68616e646f66662d746573740bff'));print(list(u))"
```
