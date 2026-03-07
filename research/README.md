# Reverse Engineering Workspace

This tree is for Jablotron protocol-reversing artifacts that should not live in the repo root.

Directory layout:

- `data ingest/`
  Temporary staging area for newly dropped bundles before they are sorted.
- `captures/usb/f_link/`
  Existing and future USB captures from F-Link sessions.
- `captures/usb/live/`
  USB captures from direct CLI or live probing against the panel.
- `captures/derived/`
  Derived text artifacts from captures, such as TSV exports or filtered packet listings.
- `fdb/before/`
  `.fdb` files saved before a single controlled change.
- `fdb/after/`
  `.fdb` files saved after the same controlled change.
- `fdb/diffs/`
  Any notes, binary diffs, or extracted comparisons derived from `.fdb` pairs.
- `exports/`
  Config exports, backups, or other files written by F-Link.
- `traces/procmon/`
  Procmon traces or similar Windows-side file activity captures around F-Link.
- `traces/process_memory/`
  Process memory dumps taken from `f-link.exe` or related tooling.
- `notes/`
  Short text notes describing exact actions, timestamps, and test values used in a capture.

Recommended capture naming:

- `YYYY-MM-DD_read-users-only.pcapng`
- `YYYY-MM-DD_add-user-U17TEST.pcapng`
- `YYYY-MM-DD_rename-user-07-to-U17TEST.pcapng`
- `YYYY-MM-DD_change-code-user-07.pcapng`
- `YYYY-MM-DD_delete-user-07.pcapng`

For high-value datasets, keep a matching note file in `notes/` with:

- panel state before the run
- exact F-Link actions taken
- usernames / codes / user numbers used
- absolute timestamps if available

Useful offline analysis commands:

- `python3 f_link_user_tool.py list-snapshots research/traces/process_memory/f-link-edit-user-USER91TEST.dmp`
- `python3 f_link_user_tool.py extract-users research/traces/process_memory/f-link-edit-user-USER91TEST.dmp --format tsv`
- `python3 f_link_user_tool.py diff-users research/traces/process_memory/f-link-delete-user-USER91TEST.dmp research/traces/process_memory/f-link-edit-user-USER91TEST.dmp`
- `python3 export_cfg_tool.py extract-users research/exports/2026-03-07_live-service_EXPORT.CFG.bin --format tsv`
- `python3 export_cfg_tool.py pull-live research/exports/live_EXPORT.CFG.bin --extract-users`
- `python3 fdb_tool.py info research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb`
- `python3 fdb_tool.py extract-users research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb --format table`
- `python3 fdb_tool.py unpack research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb /tmp/edit-user.xml --xml-only`

Notes:

- The memory dumps can contain stale heap fragments. Use `f_link_user_tool.py` to pick a coherent `JA100UsersSetup` / `TJA100AllUsers` snapshot instead of grepping loose strings across the whole dump.
- The latest complete snapshots in the current edit/delete dumps resolve the authoritative state of user 91 correctly: populated in the edit session, empty/default in the delete session.
- For live reads, `EXPORT.CFG` on `FLEXI_CFG` can stay all-zero until a F-Link-style HID session refreshes it. A captured service-session replay now exists as `python3 jablotron_usb_debug.py --code 1812 --login-first --no-reset f-link-export-session`.
- The live `EXPORT.CFG` blob is bytewise XORed with `0xff`. `export_cfg_tool.py` decodes that layer and can extract a user list directly from the pulled export blob.
- Preferred live path: `export_cfg_tool.py pull-live` triggers the service-session replay and then reads sectors directly from `/dev/sdb1` with `dd iflag=direct`, which avoids the stale mounted-file cache problem.
- `.fdb` files are not XORed. They use a 29-byte `ODBO-Link database file` header, followed by a zlib stream, followed by a decompressed payload whose XML starts at offset 16.
- `fdb_tool.py pack` can rebuild an `.fdb` container from XML or a full decompressed payload. Repacked files preserve the decompressed content, but the compressed bytes may differ from the original due to zlib recompression.
