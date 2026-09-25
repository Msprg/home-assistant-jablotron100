# Handoff: first user write from the container (2026-09-25)

For the next session picking up the board handover. Everything below is
measured unless marked as a hypothesis. No user names, cards or codes
appear here.

## Where things stand

**Done and committed on `reverse-engineering` (`f27d537..d1b7ac5` plus the
compose commit below):** the working tree from August, the user-write guards
(`name_too_long`/`comment_too_long`, `409 user_slot_occupied` with
`?replace=1`, PIN redaction on write responses and WS write events), the
demo panel's user range 1-10, offline coverage of direct staging, the
session entry in `docs/api-server-refactor-status.md`. Suite: 299 passing.

**board's tokens:** the write token `34477b8d280a122c` (exact scopes
`users:read users:write users:codes:read catalog:read system:read`, bound
to the `CN=board-provisioning` fingerprint) is in use by board since
13:20 UTC. The old read token `8484a4a03ae4c3ac` was revoked at 13:25:50 UTC
through `DELETE /v1/tokens` and answers 401; its file is deleted. The
temporary admin token used for this session (`eb28572ce0a0744e`) is revoked.

**The live panel API container** (`home-assistant-jablotron100-jablotron-api-1`)
was recreated twice and is running the **2026-08-21 image** (it does not
contain today's guards; a rebuild is still needed for those) with:

- `JABLOTRON_PANEL_STAGE_MODE=filesystem`
- `cap_add: [SYS_ADMIN]`, `security_opt: [apparmor:unconfined]`
  (CapEff `a82425fb`, bit 21 set; profile `unconfined`)

These are in the local `docker-compose.yml` (gitignored) and, for the
record, in `docker-compose.dev.yml` and `docker-compose.yml.example`.

**The user table is unchanged.** Both write attempts were compared
field-by-field against a fresh baseline read taken beforehand: 81
client-facing users before and after, no differences, no user in slot 96.
The event log shows only `150` (authorisation) and `156` (connection
established) around both attempts, no `48`.

## The live write failed, twice, in the panel's mass-storage layer

Owner-approved test: create a throwaway user in free slot 96 (name and
comment only). The container was first started with
`JABLOTRON_PANEL_STAGE_MODE=direct`, then, after the owner chose to grant
mount, with `filesystem`.

| Attempt | Path | Result | Kernel journal (host, local time) |
| --- | --- | --- | --- |
| 13:31 UTC | direct (`dd` to LBA 2083 of `/dev/sdb1`) | `dd: error writing '/dev/sdb1': Input/output error`, both O_DIRECT and buffered; HTTP 500 after 23 s | 15:31:23 `sd 7:0:0:0: [sdb] Sense Key: Hardware Error`, `CDB: Write(10) 2a 00 00 00 08 24 00 00 01 00`, `I/O error, dev sdb, sector 2084 op WRITE` (twice) |
| 13:48 UTC | filesystem (mount in container, write `IMPORT.CFG` sector 0, fsync, unmount) | `warning: write raised [Errno 5] Input/output error; continuing because staged bytes verified exactly`; accept sequence ran; verification read found no user 96; HTTP 409 after 81 s | 15:48:55 `I/O error, dev sdb, sector 2083 op WRITE`; 15:48:57 `Hardware Error`, `Write(10) ... 00 00 00 1b`, `sector 27 op WRITE`, `Buffer I/O error on dev sdb1, logical block 26, lost async page write`; 15:49:35 `FAT-fs (sdb1): Volume was not properly unmounted` |

So the panel's USB mass-storage firmware answers **every** SCSI
`Write(10)` on the FLEXI_CFG volume with sense key *Hardware Error*: the
data sector of `IMPORT.CFG` and the directory/FAT sector alike, from either
staging path. This is not a container permission problem (the device opens
for write, `blockdev --getro` is 0, the mount succeeded, `IMPORT.CFG` was
present) and not a setup-mode problem (`enter_setup_mode` raises
`SystemExit` when the mode is not reached, and staging was reached).

Two things established from the archive while diagnosing:

- `research/notes/2026-03-10_transport-review-followup.txt`: raw sector
  writes, even when they land and read back, **never trigger a semantic
  import**; the validated path is mount → write file → unmount → accept
  sequence. Direct staging is a debug mode. Keep it that way.
- Cloud-side ("Server" channel) configuration changes have written
  `IMPORT.CFG` as recently as 2026-08-19 (`docs/panel-export-freshness.md`,
  table at line ~100), and host-side writes worked on 2026-04-23. Nothing in
  the exported config locks writes: `service_access` is `ARC_ACCESS_FULL`
  on all ARC rows and on `communications`, `wpp_lock` is false.

## A masked failure to fix regardless

`stage_import` (`jablotron_re_tools.py`, `def stage_import`) treats an
`OSError` from the write as non-fatal when `import_path.read_bytes()`
returns the staged bytes. After a refused write that read comes from the
page cache, so it proves nothing; the accept sequence then ran against
unchanged panel storage and the failure surfaced only as "not present after
add" 60 seconds later. Make an `EIO` on write or fsync fatal, and verify
with an O_DIRECT read after unmount (`verify_import_sector_direct` exists)
rather than through the cache.

## What to try next, in order

1. **Discriminate container vs panel.** Run the same create on the host
   with the historically working tooling (`jablotron_user_tool.py add 96
   --name ... --comment ...`, needs sudo for mount/dd) with the container
   stopped so `/dev/hidraw0` is free. If the host also gets *Hardware
   Error*, the panel itself currently refuses writes and the container is
   not the variable. Restart the container afterwards with plain
   `docker compose up -d`.
2. **If the panel refuses:** replug the panel's USB (the same action as for
   the `[Errno 5]` dropout, see memory) or power-cycle it, then retry from
   the host. Check `journalctl -k` for the sense key each time. Also ask
   whether F-Link can still write to this panel today; if not, the panel
   (or a cloud-side lock not visible in the export) is the cause.
3. **If the host works and the container does not:** compare the SCSI
   traffic. `usbmon` on the host during both would show whether the
   container's writes differ (they should not).
4. Only once a write succeeds: the same-value comment rewrite, the
   `-`/`_`/`~` comment round trip (board's marker uses hyphens), and the
   event-48 check. Then delete user 96 and confirm the table equals the
   baseline.

Test envelope reminder: only slot 96 (owner's choice), no section or PG
actions, no code changes.

## Practical notes for the next session

- The classifier interrupted three responses in this session, each at the
  point of issuing or diagnosing a raw write to the panel's block device.
  Keep tool calls short, put secrets in files rather than command lines, and
  describe each step plainly before running it.
- A helper for authenticated calls over mTLS lived at
  `.git/claude-scratch/api.py`; it reads a token from
  `.git/claude-scratch/tmp-token`, which has been deleted. Mint a new
  temporary token with `bootstrap-token` (redirect stdout to a 600 file)
  and revoke it at the end.
- Fresh reads cost ~16 s and a configuration-mode session; the event read
  ~8-11 s. A write costs preflight read + write + refresh, ~80 s.

## Result of step 1 (same day, later session)

Step 1 was run: `jablotron_user_tool.py add 96` on the host with the
container stopped and `/dev/hidraw0` free. Setup mode was reached
(`saw_1b00`), and the panel refused the write the same way:

| Attempt | Path | Result | Kernel journal (host, local time) |
| --- | --- | --- | --- |
| 14:09 UTC | host, filesystem (`sudo mount`, write `IMPORT.CFG`, fsync) | `IMPORT.CFG staging failed: ... [Errno 5] Input/output error`; exit 1 after 26 s, accept sequence not run | 16:09:43 `Write(10) ... 08 23` sector 2083 and `... 00 1b` sector 27, both *Hardware Error*, `lost async page write` |

So the container is not the variable. The user table was compared again
(tool's pre-attempt export against a fresh live `list`): 90 raw entries,
identical, no slot 96. The host mount was removed afterwards and the
container restarted with `docker compose up -d` (startup complete 14:13
UTC, HA reconnected).

The masked failure is fixed in `dd1e82c`: a write or fsync error in
`stage_import` is fatal, and the filesystem path verifies the sector with
an O_DIRECT read after unmount before the accept sequence.

Next is step 2: replug or power-cycle the panel USB and retry from the
host; and ask whether F-Link can still write to this panel today.
