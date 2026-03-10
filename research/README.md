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
- `traces/f_link_logs/`
  Copied `%APPDATA%\\Jablotron\\FLink\\` folders containing `FLink.ini` and rotated `comm.log*.htm` communication logs.
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
- `python3 jablotron_user_tool.py list`
- `python3 jablotron_user_tool.py get 88`
- `python3 jablotron_user_tool.py add 89 --name testuser89`
- `python3 jablotron_user_tool.py edit 88 --comment 'Renamed from CLI' --use-minimal-template`
- `python3 jablotron_user_tool.py delete 89`
- `python3 import_cfg_tool.py decode-frame research/captures/usb/f_link/f-link-edit-user-USER91TEST.pcapng 1787 --format json`
- `python3 import_cfg_tool.py build-user-upsert /tmp/user91-edit.bin --user-id 91 --name USER91TEST --code 9999 --card1 0000000012200717 --comment 'THIS IS A SAMPLE USER91TEST NOTE' --permissions-raw 811 --sections-mask 63 --pg-masks 65535,0,0,0`
- `python3 import_cfg_tool.py build-user-delete /tmp/user91-delete.bin --user-id 91`
- `python3 fdb_tool.py info research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb`
- `python3 fdb_tool.py extract-users research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb --format table`
- `python3 fdb_tool.py unpack research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb /tmp/edit-user.xml --xml-only`
- `python3 enum_rtti_scan.py scan research/traces/process_memory/*.dmp --dedupe --keyword System --keyword Service --keyword Permission --keyword Authorization --keyword Access`
- `python3 property_rtti_correlation.py correlate research/fdb/after/*.fdb --dumps research/traces/process_memory/*.dmp --only-matched --keyword Permissions --keyword TimeLimitGroup --keyword PGAccess --keyword Sections`
- `python3 jablotron_noauth_probe.py probe --read-export --export-output research/exports/noauth_probe_EXPORT.CFG.bin`
- `python3 f_link_schema_tool.py extract research/traces/process_memory/f-link-schema-access-system-minidump.dmp research/exports/f-link-schema.json`
- `python3 f_link_schema_tool.py access-report research/traces/process_memory/f-link-schema-access-system-minidump.dmp`
- `python3 f_link_comm_log_tool.py decode-tree research/traces/f_link_logs/roaming_Jablotron_FLink research/exports/f_link_comm_logs_html`
- `python3 f_link_comm_log_tool.py dump-text-tree research/traces/f_link_logs/roaming_Jablotron_FLink research/exports/f_link_comm_logs_text`

Notes:

- The memory dumps can contain stale heap fragments. Use `f_link_user_tool.py` to pick a coherent `JA100UsersSetup` / `TJA100AllUsers` snapshot instead of grepping loose strings across the whole dump.
- The latest complete snapshots in the current edit/delete dumps resolve the authoritative state of user 91 correctly: populated in the edit session, empty/default in the delete session.
- For live reads, `EXPORT.CFG` on `FLEXI_CFG` can stay all-zero until a F-Link-style HID session refreshes it. A captured service-session replay now exists as `python3 jablotron_usb_debug.py --code 1812 --login-first --no-reset f-link-export-session`.
- The live `EXPORT.CFG` blob is bytewise XORed with `0xff`. `export_cfg_tool.py` decodes that layer and can extract a user list directly from the pulled export blob.
- `EXPORT.CFG` user strings are encoded with MessagePack string markers, not just `fixstr`. `export_cfg_tool.py` now handles `fixstr`, `str8`, `str16`, and `str32`, which matters once fields exceed 31 bytes.
- Preferred live path: `export_cfg_tool.py pull-live` triggers the service-session replay and then reads sectors directly from the auto-resolved `FLEXI_CFG` block device with `dd iflag=direct`, which avoids the stale mounted-file cache problem.
- `jablotron_re_tools.py` now holds the shared live-panel plumbing used by `export_cfg_tool.py`, `live_import_apply.py`, `jablotron_user_tool.py`, and the smaller smoke-test `dev_test.py`. This keeps device discovery, setup-mode entry, staging, accept, and verification in one place while preserving the lower-level scripts for reversing.
- FLEXI_CFG block-device resolution now defaults to `auto`, which prefers `/dev/disk/by-label/FLEXI_CFG` and falls back to `lsblk`. On this workstation that currently resolves to `/dev/sdc1`.
- `export_cfg_tool.py extract-users` and `pull-live --extract-users` now have two views:
  - `--user-mode dedupe` for operator-safe summaries and CRUD verification
  - `--user-mode raw` for reverse engineering when repeated record-shaped hits matter
- Current user-listing output now also prints:
  - rights label inferred from export field `1` (`0 -> coNoAccess`, `2875 -> coService`, `1851 -> coMaster`, `811 -> coUserNoSelfedit`)
  - the remaining live non-user value `827` is now labelled `WPPPhone` for IDs `603-610`, because those records line up with the communicator `WPPPhones` list in the unpacked `.fdb` XML rather than normal keypad users
  - enabled/disabled state inferred from export field `0`, where the current live/FDB evidence treats `field0 == 1` as disabled/blocked
- On this workstation, `udisksctl mount -b ...` / `udisksctl unmount -b ...` can trigger an interactive GNOME polkit prompt and appear to hang until the desktop dialog is approved. For terminal automation, prefer `sudo mount` / `sudo umount` or direct `sudo dd` block reads/writes instead of `udisksctl`.
- `IMPORT.CFG` sector 0 is also XORed with `0xff`, but after XOR reversal it decodes as MessagePack rather than an ad hoc binary format.
- Observed user mutations use top-level collection key `7`: add/edit are `{7: {<user_id>: <12-field map>}}`, delete is `{7: {<user_id>: nil}}`.
- `import_cfg_tool.py` round-trips the captured add/edit/delete sectors exactly, so user mutation sectors can now be synthesized offline without F-Link.
- A live no-op write has now been validated: deleting confirmed-empty user slot `4` left the refreshed `EXPORT.CFG` hash and parsed user map unchanged.
- The live transport path was validated first with a no-op direct sector write, but a real semantic mutation required filesystem-level staging rather than raw block writes alone.
- During that no-op test, `IMPORT.CFG` sector 0 changed from a pre-command sentinel (`false`) to the written delete command, then to a different post-refresh sentinel (`-1`), which suggests the panel consumes or clears the command after processing.
- Raw direct sector writes on `/dev/sdb1` were not enough for a real mutation. They staged data, and sometimes produced ghost copies near the end of `EXPORT.CFG`, but they did not reliably update the authoritative user table.
- Captured F-Link add/edit/delete sessions always perform a second write to `lba=27 sectors=8` after the `IMPORT.CFG` exchange, which is consistent with FAT directory metadata updates for `IMPORT.CFG`.
- A real live semantic user edit is now validated. On 2026-03-08, slot `86` (`TESTUSERWALDO`) was changed from comment `Waldo has a new comment` to `USB8`, and the new comment persisted across repeated fresh `pull-live` reads in new authenticated sessions.
- The currently working live-apply sequence is:
  - stage sector 0 of `IMPORT.CFG` through the mounted file path `/media/administrator/FLEXI_CFG/IMPORT.CFG`
  - unmount `/dev/sdb1` to flush the FAT metadata to the device
  - perform the minimal HID accept sequence: `52 01 02`, `52 01 24`, `52 01 02`, `52 01 0C`
  - optionally answer `80 01 17` with `80 01 14`, and `80 02 1A 0A` with `80 01 0F`, then an extra `52 01 02` if the panel asks for it
  - verify with a fresh `export_cfg_tool.py pull-live` in a new session
- Operational note: when reproducing that sequence from a terminal, avoid `udisksctl` if possible. On this host it may block on a desktop auth dialog; `sudo umount /dev/sdb1` and an explicit `sudo mount` are more reliable for scripted runs.
- The two post-apply verification exports are:
  - `research/exports/2026-03-08_retry3_verify_EXPORT.CFG.bin`
  - `research/exports/2026-03-08_retry4_persist_EXPORT.CFG.bin`
  - both have SHA-256 `58b83a61b614db77d3535e62b3cde1a462ebdc42e3f4ebe0cc32d839055b3615`
- `live_import_apply.py` now packages the full reusable write path: setup-mode entry, filesystem staging, unmount, import accept, optional export verification, and remount. Its current setup helper follows the matched F-Link add/delete logs more closely: wait for `80 02 1A 0A`, answer with `80 01 0F`, then send the first `52 01 02`, with a delayed `80 01 0F` nudge after `80 1A 0C ...` if `80 02 1A 0A` does not arrive on its own. It also defaults to `sudo mount` / `sudo umount` rather than `udisksctl`.
- The shared live helper now also mirrors F-Link's exit sequence for setup-mode write sessions instead of just dropping the HID handle:
  - `94 02 01 00`
  - `80 01 01`
  - `52 01 0E`
  - `52 01 02`
  - in live verbose output this ends with the same `sections_states ... 90` transition seen in the matched F-Link logs, which is strong evidence that setup/config mode was actually left
- Pure read/export sessions now use a second post-read HID cleanup pass instead of trying to close the original trigger session inline. The current shared helper supports `cleanup_mode=auto|none|exit-only|login-exit`; default `auto` triggers the export, reads `EXPORT.CFG` directly, then opens a fresh HID session to close the panel state cleanly.
- Live verification on 2026-03-10 showed that `exit-only` was not sufficient for read sessions on this panel: it ended on `sections_states ... 80`. The automatic fallback `login-exit` did reach `sections_states ... 90`, while the pulled export stayed valid at SHA-256 `f6acd86cf3ceeb2947690538d34fd35bcb212aeb39d26581c668b17ec176a8d4`.
- The earlier limitation still applies in a narrower form: applying graceful exit inline to the original minimal export-trigger session still races the refresh and returns an all-zero `EXPORT.CFG`. The working approach is to let the trigger session disconnect first, then do the graceful teardown in a second HID session after the direct block read.
- That packaged helper was revalidated on 2026-03-10 first with a no-op delete of already-empty slot `86`, then again after a real add of user `88` with a same-value upsert. The revalidation export after the user-88 add was `/tmp/2026-03-10_live-import-apply-user88-reverify_EXPORT.CFG.bin` with SHA-256 `b580cfb055dfd628eb9827823328d28176f6a7210a8497a108fee8ac3a198525`.
- Capture analysis on 2026-03-10 shows that F-Link's write path is preceded by a setup-mode transition, not just plain service authentication. The key observed bridge is `80 1A 0C ...` (service rights accepted) followed by `80 01 0F`, then `52 01 02` keepalives until `80 01 12` (`Setting mode entered`). Manual live probing reproduced that transition at least once, but the timing is still sensitive and not yet packaged into a reliable helper. See `research/notes/2026-03-10_setup-mode-handshake.txt`.
- A later scripted live run on 2026-03-10 used that setup-mode bridge to change user `86` (`TESTUSERWALDO`) from comment `USB8` to `USBA`, and a fresh post-run export confirmed the mutation. The same run also showed that direct post-apply reads of `IMPORT.CFG` sector 0 can snap back to the older `USB3` payload even when the authoritative `EXPORT.CFG` user table reflects the new value, so `IMPORT.CFG` sector 0 should not be treated as a durable record of the last successful command.
- A second scripted live run on 2026-03-10 changed the same user comment from `USBA` to `Longer comment test 2026-03-10 A` and confirmed the value in a fresh export at `/tmp/2026-03-10_post-longcomment_EXPORT.CFG.bin` with SHA-256 `fda7940ba19ce6584a90df1062e2059910041a269f7bc04313cf71d6cdf6daf4`. This also exposed and fixed an `export_cfg_tool.py` parsing bug: 32-byte comments switch from MessagePack `fixstr` to `str8`, so earlier extraction code falsely showed trailing garbage even though the panel stored the value correctly.
- Another scripted live run on 2026-03-10 changed user `86`'s name from `TESTUSERWALDO` to `TESTUSERWALDO2` while preserving the long comment, and a fresh export at `/tmp/2026-03-10_post-namechange_EXPORT.CFG.bin` confirmed the rename with SHA-256 `88e6959fdae8e566b4a54aee670541cb8ee7fc2a7f841cfea193b2daddf0d296`. This is the first live proof that field `4` in the user upsert payload controls the exported user name, not just comments. As with the comment edits, direct post-apply reads of `IMPORT.CFG` sector 0 still reverted to the older `USB3` payload, so verification should continue to rely on a fresh `EXPORT.CFG` pull.
- A later scripted live run on 2026-03-10 deleted that same user `86` successfully with the captured delete shape `{7: {86: nil}}`. The verification export at `/tmp/2026-03-10_post-delete-testuserwaldo2_EXPORT.CFG.bin` had SHA-256 `25991e1bdf8d1c968442458165b31a083c337f3bcbe2ae0f3a416daf7521fd1c`, user `86` was absent, and the parsed user count dropped from `81` to `80`. The successful retry also narrowed the setup bridge: in that run, sending `80 01 0F` immediately after `80 1A 0C ...` and only then the first `52 01 02` was enough to enter setup mode reliably, while the reverse order failed in the preceding attempt. As before, direct post-apply reads of `IMPORT.CFG` sector 0 still snapped back to the older `USB3` payload, so verification should continue to rely on a fresh `EXPORT.CFG` pull.
- A later scripted live run on 2026-03-10 added a new minimal user `88` named `testuser88` using the captured low-privilege add shape from `f-link-add-user-USER91TEST.pcapng`. The verification export at `/tmp/2026-03-10_post-add-user88_EXPORT.CFG.bin` had SHA-256 `b580cfb055dfd628eb9827823328d28176f6a7210a8497a108fee8ac3a198525`, and user `88` decoded correctly from the main user table. That add also refined the reusable setup helper again: the successful add path matched the decoded F-Link logs more closely by waiting for `80 02 1A 0A`, answering with `80 01 0F`, and only then sending the first `52 01 02`, with a delayed `80 01 0F` nudge if `80 02 1A 0A` does not appear on its own. One remaining caveat is that the refreshed export contains a second identical user-88 record near the end of the blob, so raw parsed-record counts can overcount by one; user summaries should dedupe by user ID.
- The user-management workflow was refactored again on 2026-03-10:
  - `jablotron_user_tool.py` now provides the operator-facing `pull-export`, `list`, `get`, `add`, `edit`, and `delete` commands
  - the old Home Assistant-oriented `dev_test.py` moved to `legacy/dev_test_homeassistant_legacy.py`
  - the new `dev_test.py` is a smaller smoke-test CLI for the current live RE path
  - live verification with the new CLI succeeded for a same-value edit of user `88`, an add of user `89` (`toolsmoke89`), and a delete of that same user `89`
  - interestingly, the post-delete export `/tmp/2026-03-10_user-tool-delete89_EXPORT.CFG.bin` had SHA-256 `a69d5fc13338f0bffcb9b4c3f571189ddc0c8662db606fb55b1b47022bb18a0d`, and the earlier raw ghost copy of user `88` had disappeared, leaving `users_raw 81` and `users_deduped 81`
  - the shared parser now exposes two additional user columns:
    - rights label from raw field `1`
    - enabled state from raw field `0`
  - known examples from the current live export:
    - user `7` decodes as `coService` and enabled
    - users `13`, `34`, and `39` decode as `coUserNoSelfedit` and disabled
- `.fdb` files are not XORed. They use a 29-byte `ODBO-Link database file` header, followed by a zlib stream, followed by a decompressed payload whose XML starts at offset 16.
- `fdb_tool.py pack` can rebuild an `.fdb` container from XML or a full decompressed payload. Repacked files preserve the decompressed content, but the compressed bytes may differ from the original due to zlib recompression.
- `enum_rtti_scan.py` can recover Delphi RTTI enum definitions directly from the F-Link process dumps; the current deduped catalog contains 162 enum definitions.
- `property_rtti_correlation.py` correlates `.fdb` `tkEnumeration` and `tkSet` properties with the RTTI enum catalog. Current high-confidence mappings include `Permissions -> TJA100PermissionsEnum`, `TimeLimitGroup -> TJA100UserTimeLimitEnum`, `PGAccess -> TJA100PGEnum`, `Sections/SectionMask -> TJA100SectionEnum`, and `IsNull`/`ReadOnly`/`Updated -> Boolean`.
- `jablotron_noauth_probe.py` confirms a limited unauthenticated metadata leak over HID: model, hardware version, firmware version, registration code, installation name, and section/PG state packets are readable without sending any authorisation code.
- The same no-auth probe does not populate `EXPORT.CFG`: direct O_DIRECT reads after the unauthenticated trigger still return an all-zero 1 MiB blob, so the current evidence does not support pre-auth reading of the full config export or user table.
- Procmon-guided collection confirmed that F-Link stores communication logs under `%APPDATA%\\Jablotron\\FLink\\` as `comm.log.htm` plus rotated `comm.log.N.htm` files, alongside `FLink.ini`.
- Running `F-Link.exe /?` confirmed that communication logging is a supported command-line feature: `-commlog` / `--commlog` means `Log comunication to a file`.
- The same help dialog also confirmed the following built-in switches: `-defcodes`, `-langcheck`, `-notimeout`, `-offline`, `-notheme`, `-hlimit x`, `-ownevtxt`, and `-noinvalidate`.
- The process dumps contain one UTF-16 help-string table holding `comm.log.htm`, `-commlog`, `--commlog`, `Log comunication to a file`, `-defcodes`, `--defcodes`, and `Use default central codes`, so those hits are real command-line help text rather than orphaned strings.
- A panel event-log export is now archived as `research/exports/2026-03-08_panel-event-log.csv`; it confirms that successful USB config applies generate `Zmena konfigurácie` followed shortly by `Created backup configuration`, while failed probes show `Neplatná autorizace`.
- Other schema/translation strings in the dumps explain what `-defcodes` is likely meant to use:
  - the service code is kept in user/code position `0`
  - the main administrator code is kept in position `1`
  - factory defaults are explicitly documented as administrator `12345678` and service `10101010`
  - `cfg.ja100.systemparams.warndefaultcodes` warns by SMS when default access codes are still in use after leaving service mode
- Current interpretation: `-defcodes` / `--defcodes` most likely tells F-Link to use the panel's built-in factory default administrator/service codes when connecting.
- The copied `comm.log*.htm` files in `research/traces/f_link_logs/roaming_Jablotron_FLink` are now decoded: they are UTF-8 HTML logs wrapped by F-Link's `TObfuscatedLogStream`, not encrypted with Windows CryptoAPI.
- The successful decode path comes from `TObfuscatedLogStream` methods at `0x00702314` (`Create`), `0x00702350` (`Read`), and `0x00702388` (`Write`), using the 256-byte XOR table at virtual address `0x011DBE31`.
- The stream wrapper keeps a one-byte rolling key position that starts at zero for each file and XORs each byte with `table[index & 0xff]`, incrementing the index after every byte.
- `f_link_comm_log_tool.py` implements that exact decode path and can bulk-decode copied `%APPDATA%\\Jablotron\\FLink\\comm.log*.htm` files to HTML or plaintext without requiring the original executable.
- The decoded logs contain directly useful protocol/runtime evidence, including `Rx:` / `Tx:` frame dumps, talker lifecycle messages such as `JA100_GET_DEVICE_DESCRIPTOR`, `JA100_READ_FL_VAR`, and `JA100_EXIT_AUTHORISATION`, plus device-mount details like `FLEXI_CFG`, `FLEXI_LOG`, `THIDCommThread`, and `TJA100StreamedFileComm`.
- The decoded log set in `research/exports/f_link_comm_logs_text/` and `research/exports/f_link_comm_logs_html/` was pruned on 2026-03-10 to the scenario-matched files only. The retained pairs are now named after the corresponding packet captures:
  - `f-link-base-read.from-comm.log.8`
  - `f-link-add-user-USER91TEST.from-comm.log.7`
  - `f-link-edit-user-USER91TEST.from-comm.log.6`
  - `f-link-delete-user-USER91TEST.from-comm.log.4`
  - `f-link-edit-user-TESTUSERWALDO-comment-only.from-comm.log.2`
- The matching rationale and timing evidence are recorded in `research/notes/2026-03-10_f-link-comm-log-pairings.txt`.
- `f-link-schema-access-system-minidump.dmp` contains an embedded JSON schema blob with internal type and field definitions. `f_link_schema_tool.py` can extract it and generate an access-focused report.
- That embedded schema confirms a distinct software-only internal privilege tier above normal service access: `ACCESS_SYSTEM` (`def=15`) and `COMP_SYSTEM`.
- The schema also exposes access gates for stored config groups via `cfg_data_t`, for example:
  - `user`: `r_access=+ACCESS_SERVICE+ACCESS_MASTER+ACCESS_USER`, `w_access=+ACCESS_SERVICE+ACCESS_MASTER`
  - `system`: `r_access=+ACCESS_SERVICE`, `w_access=+ACCESS_SERVICE`
  - `users_time_limit`: `r_access=+ACCESS_SERVICE+ACCESS_MASTER+ACCESS_USER`, `w_access=+ACCESS_SERVICE+ACCESS_MASTER`
- `cfg_user_t.access` maps directly to `access_t` with F-Link record name `Permissions`, which helps bridge the internal access model to the exported/imported user records.
