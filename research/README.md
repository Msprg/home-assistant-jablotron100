# Jablotron 100 Reverse Engineering Workspace

This tree is the reference documentation and artifact store for everything learned about
the Jablotron 100 USB protocol, `EXPORT.CFG` / `IMPORT.CFG` storage formats, F-Link
behaviour, and the live-panel tooling that reproduces each of those paths from Linux.

The top-level Python tools that implement the findings here live in the repository root
(`export_cfg_tool.py`, `import_cfg_tool.py`, `jablotron_user_tool.py`,
`jablotron_event_tool.py`, `jablotron_arc_tool.py`, `f_link_schema_tool.py`,
`f_link_i18n_tool.py`, `f_link_comm_log_tool.py`, `fdb_tool.py`, etc.).

Start with [`research/2026-03-07_usb-protocol-research-report.md`](2026-03-07_usb-protocol-research-report.md)
for the original breakthrough narrative, then use this README as the authoritative
cross-referenced summary of what is currently known.

For static analysis of the Windows application, see
[`2026-07-13_f-link-component-map.md`](2026-07-13_f-link-component-map.md). It maps the
major F-Link subsystems to recovered Delphi types and executable virtual addresses and
provides entry points for deeper reverse engineering.
The follow-up
[`2026-07-14_f-link-boundary-callgraphs.md`](2026-07-14_f-link-boundary-callgraphs.md)
resolves the priority RTTI records to VMTs and published methods, bounds the firmware
state machine, and records the package-to-transport call graph.
The communication-focused continuation,
[`2026-07-14_f-link-communication-protocol-boundaries.md`](2026-07-14_f-link-communication-protocol-boundaries.md),
recovers direct-HID and streamed transport VMTs, application framing, fragment
reassembly, heartbeat/retry layers, and exact next targets for a more robust client.
The implementation sequence is tracked in
[`2026-07-14_api-server-communication-roadmap.md`](2026-07-14_api-server-communication-roadmap.md),
which turns those findings into staged codec, dispatcher, liveness, write-reliability,
correlation, and rollout work for the API server.

---

## 1. Directory layout

- `data ingest/` - staging area for newly dropped bundles before they are sorted.
  External reference material also lives under
  `data ingest/external reference resources/` (for example `Peskova.fdb`, `Peskova F-Link.DMP`).
- `captures/usb/f_link/` - pcapng captures of F-Link USB sessions.
- `captures/usb/live/` - pcapng captures of direct CLI / live probing runs.
- `captures/derived/` - derived text exports from captures (TSV, filtered packet lists, etc.).
- `traces/f_link_logs/` - copied `%APPDATA%\Jablotron\FLink\` folders containing
  `FLink.ini` and rotated `comm.log*.htm` communication logs.
- `traces/procmon/` - Procmon / file-activity traces.
- `traces/process_memory/` - F-Link process minidumps.
- `fdb/before/` and `fdb/after/` - `.fdb` snapshots taken before and after a single
  controlled F-Link change.
- `fdb/diffs/` - notes and binary diffs extracted from `.fdb` pairs.
- `exports/` - decoded or panel-pulled artifacts: `EXPORT.CFG` / `IMPORT.CFG` blobs,
  embedded schema JSON, RTTI catalogues, i18n catalogues, decoded comm logs.
- `notes/` - dated notes describing specific experiments, handshakes, matrices, and
  interpretation changes.
- `2026-03-07_usb-protocol-research-report.md` - the original breakthrough report.

Recommended capture naming: `YYYY-MM-DD_short-description.pcapng` plus a matching note
in `notes/` with panel state before/after, exact F-Link actions, and absolute timestamps.

---

## 2. Device exposure on Linux

On this workstation the panel enumerates as:

- USB ID `16d6:0008 JABLOCOM s.r.o. JA-100 Flexi`
- Mass-storage LUN 0 - `FLEXI_CFG` on `/dev/sdb1` (contains `EXPORT.CFG` and `IMPORT.CFG`)
- Mass-storage LUN 1 - `FLEXI_LOG` on `/dev/sdc1` (contains `FLEXILOG.TXT`,
  `FLEXILOG.OLD`, `LOGINDEX.BIN`)
- HID interface on `/dev/hidraw0`

`FLEXI_CFG` is auto-mounted read/write by the desktop stack. On this host
`udisksctl mount -b .../unmount -b ...` can block on a GNOME polkit prompt; scripted
tooling therefore uses `sudo mount` / `sudo umount` (or direct `sudo dd`) and resolves
block devices through the shared `jablotron_re_tools.resolve_device` helper
(`auto` -> `/dev/disk/by-label/FLEXI_CFG` -> `lsblk` fallback). `FLEXI_LOG` resolution
behaves identically.

With the `hidraw` udev rule installed the Python tooling runs as the normal user. Do
**not** run the tools via `sudo` - historical `sudo python3 ...` runs left
root-owned `__pycache__` trees in the repo (one-time cleanup was
`sudo rm -rf ./__pycache__ ./custom_components/jablotron100/__pycache__`).

---

## 3. Live read path - `EXPORT.CFG`

### 3.1 Transport

The live panel does **not** keep `EXPORT.CFG` populated continuously. It is refreshed
only after an authenticated HID session replays the captured F-Link service-session
setup. The minimum working replay is wrapped in
`python3 jablotron_usb_debug.py --code 1812 --login-first --no-reset f-link-export-session`.

The mounted `/media/administrator/FLEXI_CFG/EXPORT.CFG` view is **not authoritative**
on Linux: the page cache can keep showing an older blob even after the device-side file
has changed. Always read the 1 MiB window directly from the block device:

```bash
sudo dd if=/dev/sdb1 bs=512 skip=35 count=2048 iflag=direct status=none of=live_EXPORT.CFG.bin
```

`export_cfg_tool.py pull-live` packages the trigger-and-read cycle and also runs a
second post-read HID cleanup session (`cleanup_mode=auto|none|exit-only|login-exit`,
default `auto`) so the panel reaches `sections_states ... 0x90` cleanly instead of
sitting in configuration mode until timeout. Applying graceful exit inline to the
original trigger session races the refresh and returns an all-zero blob; the two-phase
"trigger, direct read, second cleanup session" pattern is the reliable one.

The synthesised refresh packets include a fresh info-log blob per session and the
helper waits for the real `52 07 83 01 25 ...` reload-complete marker before reading
`EXPORT.CFG` (older versions replayed a stale hard-coded blob then slept four seconds).

### 3.2 On-disk layout

- `EXPORT.CFG` starts at LBA 35 and is 1 MiB.
- Every byte in the pulled blob is XOR-masked with `0xff`; undoing that produces a
  MessagePack document.
- After XOR reversal `export_cfg_tool.py` can extract:
  - the user table (collection `0x07`),
  - the broader panel-derived catalog (section / user-time-limit / periphery /
    PG / ARC / time-limit / object / hardware tables), and
  - the top-level main/communications blocks.

### 3.3 EXPORT.CFG top-level map

Collection IDs observed in `EXPORT.CFG` match the `cfg_data_t` top-key numbering in the
embedded schema (see section 6):

| ID (hex) | Schema key                                    | Content                                          |
| -------- | --------------------------------------------- | ------------------------------------------------ |
| `0x02`   | `KEY_cfg_data_t__main`                        | `cfg_main_t` - panel name, language, `wpp_dedicated`, code length, etc. |
| `0x05`   | `KEY_cfg_data_t__communications`              | `cfg_communications_t` - comm flags, YTUN URL, AES/YTUN/RF keys, channel mapping |
| `0x06`   | `KEY_cfg_data_t__section`                     | section names                                    |
| `0x07`   | `KEY_cfg_data_t__user`                        | full user records (the main user table)          |
| `0x08`   | `KEY_cfg_data_t__users_time_limit`            | user time-limit groups                           |
| `0x09`   | `KEY_cfg_data_t__periphery`                   | named objects (panel, peripherals, and communicator-style IDs such as `233 LAN communicator`, `234 GSM communicator`, `235 Landline communicator`, `237 Power supply`) |
| `0x0C`   | `KEY_cfg_data_t__pg_setup`                    | PG names                                         |
| `0x11`   | `KEY_cfg_data_t__arc_setup`                   | `cfg_arc_t` rows                                 |

The `main` and `communications` top-level maps are not always present at offset 0;
older captures (notably the 2026-03-21 post-unlock export) started directly with
collection records. `extract-catalog` reports `main_config`/`communications` as
`yes`/`no` per blob; when present, `extract-communications` decodes them fully.

### 3.4 EXPORT.CFG user record shape (`cfg_user_t`)

The 12-field user map decoded by `export_cfg_tool.py` and `import_cfg_tool.py`:

| Field | Name                  | Notes                                                               |
| ----- | --------------------- | ------------------------------------------------------------------- |
| `0`   | `flags`               | bit 0 = `CFG_USER_F_OFF` (blocked), bit 1 = logging suppression.    |
| `1`   | `access`              | `access_t` / F-Link record name `Permissions`. See section 7.       |
| `2`   | `section_access`      | 16-bit section bitmask (sections 1..15).                            |
| `3`   | `pg_access`           | array of four `uint32_t` masks (`CFG_MAX_PGS = 128`).               |
| `4`   | `name`                | user name (MessagePack `fixstr`/`str8`/`str16`/`str32`).            |
| `5`   | `phone`               | user phone (same string encoding).                                  |
| `6`   | `code`                | user PIN without the `NN*` user prefix.                             |
| `7`   | `rfid`                | two access-card slots (`card1`, `card2`).                           |
| `8`   | `pg_num_if_ring`      | decoded but not yet exercised live.                                 |
| `9`   | `time_limited_group`  | index into `users_time_limit` groups (`0` means unbound).           |
| `10`  | `comment`             | free-form comment.                                                  |
| `11`  | `parent_user_no`      | decoded but not yet exercised live.                                 |

`export_cfg_tool.py` always parses the full 12-field map per record. An earlier
byte-scan-based parser false-negatived user `4` (`jaroslav kardos`) because the
one-byte user ID `0x04` collided with field tag `4` ("Name"); a similar structural
bug truncated user `5`'s phone and user `6`'s code. Those regressions are fixed.

Rights labels are inferred from the raw `access` value. The known direct mappings are:

| Raw  | Label                                                                       |
| ---- | --------------------------------------------------------------------------- |
| 0    | `coNoAccess`                                                                |
| 1    | `coPanic`                                                                   |
| 2    | `coPGOnly`                                                                  |
| 256  | `coArmOnly`                                                                 |
| 799  | `coUserGuard`                                                               |
| 811  | `coUserNoSelfedit` (plus `coUserTimeLimitedNoSelfedit` when `time_limited_group > 0`) |
| 827  | `coUser` for regular panel users; `WPPPhone` for IDs `603..610` (those records line up with the communicator's `WPPPhones` list in the unpacked `.fdb`). `827 + time_limited_group > 0 -> coUserTimeLimited`. |
| 1851 | `coMaster`                                                                  |
| 2875 | `coService`                                                                 |
| 4639 | `coPCOGuard`                                                                |
| 6971 | `coPCO`                                                                     |

The confirmation set for `coNoAccess`, `coUserGuard`, `coPanic`, `coPGOnly`,
`coArmOnly`, `coUserNoSelfedit`, and `coPCOGuard` came from the reference file
`research/fdb/after/VO-66_after-add-test-rights-users-80-86.fdb`, which was built by
populating slots 80-86 with the corresponding F-Link roles.

### 3.5 EXPORT.CFG `cfg_communications_t` and `cfg_comm_flags_t`

`export_cfg_tool.py extract-communications` decodes the communicator block in full,
including the bitfield struct at `cfg_communications_t.flags` (`cfg_comm_flags_t`):

| Bit | Name                       | Meaning (from embedded schema `info`)                           |
| --- | -------------------------- | ---------------------------------------------------------------- |
| 0   | `pcos_on`                  | ARC channels enabled                                            |
| 1   | `ytun_persistent`          | persistent YTUN session 0 expected                              |
| 2   | `voice_menu_without_code`  | voice menu accessible without code                              |
| 3   | `ytun_log_disable`         | disable YTUN event log                                          |
| 4   | `wpp_lock`                 | WPP portal has asserted a lock on this config                   |
| 5   | `ytun_device_info_disable` | hide device info over YTUN                                      |
| 6   | `ytun_enable`              | YTUN transport enabled                                          |
| 7   | `comm_configured`          | communicator considered configured                              |
| 8   | `gsm_autoconfig_disabled`  | disable GSM modem auto-config                                   |
| 9   | `send_sms_on_failed_arm`   | SMS on failed arming attempt                                    |

Current live read on the saved `research/exports/2026-03-07_live-service_EXPORT.CFG.bin`
surfaces (edited for brevity):

```
main | name='VO 66 TEST' | wpp_dedicated=True | default_config=False
communications | service_access=ARC_ACCESS_OFF | ytun_url='ytun5.jablotron.cz:8087'
    | wpp_lock=True | ytun_persistent=True | ytun_enable=True | comm_configured=True
    | sdc_position=234:GSM communicator | sdc_flags=1
```

`extract-communications` and `extract-catalog` also surface readable transport
secrets when the blob includes them: `aes_key_ascii` / `aes_key_hex`, `ytun_key`,
`rf_key_ascii` / `rf_key_hex`. For ARC rows, `extract-arcs` also exposes the
protocol-specific `crypt_key` fields (see section 7.4).

---

## 4. Live write path - `IMPORT.CFG`

### 4.1 Sector format

- `IMPORT.CFG` starts at LBA 2083 and is 1 MiB.
- Only the first 512-byte sector matters for command application.
- The sector is XORed with `0xff` on storage; after XOR it decodes as MessagePack.
- Trailer `c1 c1 c1 c1` is followed by `ff` filler to the end of the sector.
- `import_cfg_tool.py` round-trips every captured add / edit / delete sector exactly
  byte-for-byte, so the serialisation layer is fully understood.

### 4.2 Observed mutation shapes

- User upsert - `{7: {<user_id>: <12-field map>}}` (top-key `7` = `KEY_cfg_data_t__user`).
- User delete - `{7: {<user_id>: nil}}`.
- Sparse field patch - `{<top_key>: {<sub_field>: <value>}}`. This has been used live
  for the ARC/service-access unlock as `{5: {12: 0}}` (see section 7.2).

### 4.3 Applying a command live

Raw block-sector writes to `IMPORT.CFG` sector 0 are **not** enough to trigger a real
mutation. The panel only accepts the command when the sector arrives through the
expected filesystem-level staging path plus the F-Link-style HID import handshake.
The 2026-03-08 `TESTUSERWALDO` comment edit was the first live proof of the whole
sequence; subsequent runs confirmed add, edit, delete, sections-only, PGs-only, and
single-field preservation edits.

The current working sequence (wrapped in `live_import_apply.py` and reused by every
higher-level tool):

1. Enter authenticated setup mode (section 4.4).
2. Stage the built sector through the mounted file path
   `/media/administrator/FLEXI_CFG/IMPORT.CFG`. On this host `stage_import()` falls
   back to a separate `sudo dd` file-prefix write when the mount is not user-writable.
3. `sudo umount /dev/sdb1` so the FAT metadata update is flushed to the device (the
   captured F-Link sessions also show a consistent late write at
   `lba=27 sectors=8`, which matches a FAT directory update for `IMPORT.CFG`).
4. Send the import-accept HID sequence: `52 01 02`, `52 01 24`, `52 01 02`, `52 01 0C`.
   Optionally answer `80 01 17 -> 80 01 14` and `80 02 1A 0A -> 80 01 0F` and follow
   with an extra `52 01 02` if the panel prompts.
5. Mirror F-Link's write-session exit: `94 02 01 00`, `80 01 01`, `52 01 0E`,
   `52 01 02`. If that inline exit ends on `sections_states ... 0x80`, the helper
   opens a second HID cleanup session (`write_cleanup_mode=auto` by default) so the
   panel reaches `... 0x90` cleanly.
6. Verify with a fresh `export_cfg_tool.py pull-live` **in a new authenticated
   session** - it is the authoritative post-apply source.

Direct O_DIRECT reads of `IMPORT.CFG` sector 0 after apply are **not** a reliable
verification oracle. Observed behaviour: for some payloads the post-apply sector still
decodes as the last older upsert payload (`USB3`) even though `EXPORT.CFG` confirms the
new value. `IMPORT.CFG` sector 0 should be treated as a transient scratchpad, not a
durable record of the last command.

Live no-op validation (2026-03-07, deleting already-empty user `4`) produced an
unchanged export hash, confirming that the panel consumes no-op commands without any
collateral effect.

### 4.4 Setup-mode handshake

Write sessions require the panel to report `Setting mode entered` (`Rx: 80 01 12`)
before `IMPORT.CFG` staging will stick. F-Link drives this from a plain authenticated
HID session through a short bridge:

- `Tx: 80 08 03 <ascii service code>` - service-code entry.
- `Rx: 80 1A 0C ...` - service rights accepted.
- `Tx: 80 01 0F` - bridge into setup mode (current best-known packet).
- `Tx: 52 01 02` keepalives.
- `Rx: 80 02 1A 0A` - panel prompt.
- `Tx: 80 01 0F` again - answer.
- `Rx: 80 02 1B 00`.
- `Rx: 80 01 12` - `Setting mode entered`.

The bridge is **timing and order sensitive**. The reliable pattern (matched against
both the successful scripted runs and the decoded F-Link comm logs):

1. Wait for `80 1A 0C ...`.
2. If `80 02 1A 0A` does not arrive shortly, proactively nudge with `80 01 0F`.
3. When `80 02 1A 0A` arrives, answer with `80 01 0F`.
4. Only then begin sending `52 01 02` keepalives until `80 01 12` appears.

`coPCOGuard` / `ACCESS_ARC` is **not** equivalent to an F-Link ARC-technician login:
a panel user with `coPCOGuard` cannot log into F-Link that way. The F-Link ARC-service
restriction is a separate stored communicator policy gate (see section 7.2).

Full packet-level reconstruction:
[`notes/2026-03-10_setup-mode-handshake.txt`](notes/2026-03-10_setup-mode-handshake.txt).

---

## 5. FDB container format

`.fdb` files are the F-Link backup format. They are not XOR-obfuscated.

- 29-byte fixed header: `00 00 00 "ODBO-Link database file" ff ff ff`.
- Immediately followed by a zlib stream.
- Decompressed payload starts with a 16-byte preamble whose value, in every sample so
  far, is `d41d8cd98f00b204e9800998ecf8427e` - the MD5 of the empty string. Its exact
  semantic role is unconfirmed; repack tooling preserves it verbatim.
- XML begins at decompressed offset 16.

`fdb_tool.py` supports `info`, `unpack` (XML or full payload), `pack` (from XML or
payload, cloning header and preamble from a template), and `extract-users`. The
repacker is structurally valid: decompressed payloads round-trip identically, but the
compressed byte stream may differ due to zlib recompression choices. F-Link acceptance
of a modified repack has not yet been validated.

The XML exposes rich config: `<database name="JA107" ...>`, `TJA100AllUsers`,
`TJA100BasicSetup`, `TJA100CommonCom`, `TJA100GSMCom`, per-peripheral classes, section
and PG names, and so on. See section 7.3 for the Peskova vs VO-66 role comparison.

---

## 6. Embedded schema and documentation mining

### 6.1 F-Link embedded schema

`f_link_schema_tool.py` extracts and inspects a JSON schema blob embedded in F-Link
minidumps (`research/exports/2026-03-08_f-link-embedded-schema.json`). The schema is
source-derived: it lists every persisted field with its class, default, access gates
(`r_access`, `w_access`), and the Czech/ASCII-Czech internal dev comments Jablotron's
developers left on the type definitions (`info`, `text`, `comment`).

Key subcommands:

- `extract <dump> <out.json>` - pull the schema out of a dump.
- `show <schema> <path>` - print one node (for example
  `MODULE(cfg_storage_types).cfg_communications_t.class.service_access`).
- `access-report <dump>` - summarise access gates in the extracted schema.
- `dev-comments <schema>` - flat index of every commented node. Supports `--path`
  and `--search` filters and `--format text|json`.

Published index:
`research/exports/2026-04-23_f-link-embedded-schema_dev-comments.{txt,json}` - 372
commented nodes extracted from the shipping F-Link 2.9.2.1509 build.

### 6.2 F-Link translation catalogues

`f_link_i18n_tool.py` parses the shipped `.lng` files and memory-dump strings into a
consolidated JSON catalogue of all F-Link UI labels and long descriptions
(`key = Label|Long description`). Subcommands: `extract`, `show`, `search`, `list`,
`info`, `diff`.

Published indexes:

- `research/exports/2026-04-23_f-link-i18n-catalog.json` - 23 shipped locales (CS, DA,
  DE, EL, EN, ES, FI, FR, HR, HU, IT, NL, NO, PL, PT, RO, RU, SK, SL, SR, SV, TR, VI),
  4141 keys per locale, source
  `research/data ingest/F-Link 2.9.2.1509/Languages/*.lng`.
- `research/exports/2026-04-23_f-link-i18n-from-dump.json` - same catalogue shape
  recovered from `research/data ingest/external reference resources/Peskova F-Link.DMP`,
  used as a fallback and regression check for builds without the `.lng` files.

The embedded-schema `info` fields (Jablotron's internal dev comments) and the i18n
catalogues (F-Link's end-user help text) are the two independent source-level
documentation seams. Joining on the `cfg` key identifiers gives a field-by-field
mapping between C struct comments and UI labels - for example
`cfg_main_t.wpp_dedicated` has the dev comment
`pro FL, komunikace na portal WPP (specificke nastaveni vseho)` and the F-Link label
`cfg.ja100.basic.wppdedicated = Communication type | Selecting one of these options
determines the type of communication.`

### 6.3 Delphi RTTI catalogues

`enum_rtti_scan.py` recovers Delphi RTTI enum definitions from the F-Link process
dumps. The current deduped catalogue
(`research/exports/2026-03-08_rtti-enum-catalog.{json,txt}`) contains 162 enum
definitions.

`property_rtti_correlation.py` correlates `.fdb` `tkEnumeration` and `tkSet` properties
against that catalogue. Current high-confidence mappings include
`Permissions -> TJA100PermissionsEnum`, `TimeLimitGroup -> TJA100UserTimeLimitEnum`,
`PGAccess -> TJA100PGEnum`, `Sections` / `SectionMask -> TJA100SectionEnum`, and
`IsNull` / `ReadOnly` / `Updated -> Boolean`.

### 6.4 F-Link comm log decoding

The `comm.log*.htm` files copied from `%APPDATA%\Jablotron\FLink\` are **not**
CryptoAPI-encrypted. They are wrapped by F-Link's `TObfuscatedLogStream`:

- Constructor `0x00702314`, read `0x00702350`, write `0x00702388`.
- 256-byte XOR table at virtual address `0x011DBE31`.
- One-byte rolling key position starts at zero per file; each byte is XORed with
  `table[index & 0xff]` and the index increments after every byte.

After undoing the XOR the payload is plain UTF-8 HTML using F-Link's `Application log`
template. `f_link_comm_log_tool.py` implements `decode`, `dump-text`, `decode-tree`,
and `dump-text-tree`. Decoded pairs (pcap capture + comm.log) are filed under
`research/exports/f_link_comm_logs_{html,text}/` with the matching names below
(rationale and timing evidence in
[`notes/2026-03-10_f-link-comm-log-pairings.txt`](notes/2026-03-10_f-link-comm-log-pairings.txt)):

- `f-link-base-read.from-comm.log.8`
- `f-link-add-user-USER91TEST.from-comm.log.7`
- `f-link-edit-user-USER91TEST.from-comm.log.6`
- `f-link-delete-user-USER91TEST.from-comm.log.4`
- `f-link-edit-user-TESTUSERWALDO-comment-only.from-comm.log.2`

The decoded logs contain `Rx:` / `Tx:` hex frame dumps, talker lifecycle events
(`JA100_GET_DEVICE_DESCRIPTOR`, `JA100_READ_FL_VAR`, `JA100_EXIT_AUTHORISATION`,
`JA100_READ_CFG`, `JA100_READ_CFG_STREAM`, `JA100_READ_CFG_VERSION`,
`JA100_MASS_STORAGE_READ/WRITE`, `JA107_IMPORT_CFG`, `JA100_APPLY_SETTINGS`), and
transport context such as `THIDCommThread`, `THIDRecvThread`, `TJA100StreamedFileComm`.

### 6.5 F-Link command-line switches

`F-Link.exe /?` confirms the following built-in switches, all traceable to the same
UTF-16 help-string table inside the dumps:

- `-commlog` / `--commlog` - `Log comunication to a file`
  (matches `comm.log.htm` rotation under `%APPDATA%\Jablotron\FLink\`).
- `-defcodes` / `--defcodes` - `Use default central codes`. Cross-referenced strings
  document that user/code position `0` is the service code, position `1` is the main
  administrator code, and the factory defaults are administrator `12345678` and
  service `10101010`; `cfg.ja100.systemparams.warndefaultcodes` is the matching SMS
  warning string. Best current interpretation: this switch tells F-Link to connect
  using those factory defaults rather than the currently configured real codes.
- `-langcheck`, `-notimeout`, `-offline`, `-notheme`, `-hlimit x`, `-ownevtxt`,
  `-noinvalidate`.

---

## 7. Access control, service-access gates, and unlock strategy

### 7.1 Internal privilege model

The embedded schema confirms the privilege hierarchy in use:

- `access_e` - `ACCESS_SYSTEM` (`def=15`) is a software-only tier above every
  externally assignable role.
- `competence_e` - `COMP_SYSTEM` mirrors that software-only tier.
- `cfg_user_t.access` maps to `access_t` with F-Link record name `Permissions`, which
  is what bridges the embedded access model to the exported/imported user records.

`cfg_data_t` applies access gates per stored config group, for example:

- `user`: read `+ACCESS_SERVICE+ACCESS_MASTER+ACCESS_USER`,
  write `+ACCESS_SERVICE+ACCESS_MASTER`.
- `system`: read/write `+ACCESS_SERVICE`.
- `users_time_limit`: read `+ACCESS_SERVICE+ACCESS_MASTER+ACCESS_USER`,
  write `+ACCESS_SERVICE+ACCESS_MASTER`.

Practical implication: `coService` is the highest **externally assignable** service
role exposed in F-Link, but the schema's storage model has a strictly higher
software-only tier. The root `cfg_data_t` object itself is gated with
`r_access=ACCESS_SYSTEM` / `w_access=ACCESS_SYSTEM`; the familiar F-Link groups are
narrower overrides inside that system-level root. The current evidence does **not**
show a broad list of individual leaf fields tagged with `+ACCESS_SYSTEM`; the
`ACCESS_SYSTEM` tier is structural rather than per-field.

### 7.2 Communicator service-access gate (proven live)

Changing `cfg_communications_t.service_access` alone is enough to unlock the
ARC/PCO editing page in F-Link for a plain service session. Live-proven on
2026-03-21; details in
[`notes/2026-03-21_arc-service-access-unlock.txt`](notes/2026-03-21_arc-service-access-unlock.txt).

- Schema: `cfg_communications_t.service_access` → `cfg_comm_service_access_e`.
  `0 = ARC_ACCESS_FULL`, `1 = ARC_ACCESS_OFF`, `2 = ARC_ACCESS_READ`. Schema `info`:
  `slouzi jen pro flink - Pristup servisniho technka (0==Ano/1==Ne/2==pouze pro cteni)`.
- Sparse `IMPORT.CFG` payload: `{5: {12: 0}}` - top-key `5`
  (`KEY_cfg_data_t__communications`), sub-field `12`
  (`KEY_cfg_communications_t__service_access`).
- Operator wrapper - `jablotron_arc_tool.py`:
  - `build-sector --mode full|off|read` - emit the sparse `IMPORT.CFG` sector.
  - `set-live --mode full|off|read` - stage, apply via setup-mode import, and pull
    fresh verification.

Important verification boundary: the 2026-03-21 post-write export did not expose a
full `cfg_communications_t` block at offset 0, so the final confirmation came from
F-Link UI behaviour (the new editable PCO page appearing) rather than an offline
re-read of field `12`. Later `extract-communications` work now does decode the
`service_access` field when the blob contains it, so this verification is recoverable
going forward.

### 7.3 Peskova reference vs VO-66

The external reference backup
`research/data ingest/external reference resources/Peskova.fdb` is a standalone
residential JA-107 (`SystemName "Pešková RD"`, firmware `MD6112.07.0`, 2 sections,
5 users, 12 peripherals, no ARC, no dedicated Jablotron SIM, stock backend
`ytun7.jablotron.cz:8089`). VO-66 is the same JA-107 model on firmware `MD6112.09.1`
with 21 active ARC rows, an SDC-managed SIM (`APN=sdc.jablotron`, `ModemType=gmtQuectelEGxx`,
`SimPredefined=gspSdc`, `SDC=True`, `DisableOperatorSwitch=True`), and the SDC WPP
backend `ytun5.jablotron.cz:8087`.

Diffing their decompressed XML isolated the value deltas that actually drive the
F-Link privilege difference. None of the differences are schema-missing fields; they
are all value differences in fields both panels support:

| Property (`.fdb` / F-Link UI)              | Peskova  | VO-66            | Schema path                                           | Sparse address                            |
| ------------------------------------------ | -------- | ---------------- | ----------------------------------------------------- | ----------------------------------------- |
| `TJA100CommonCom.ServiceAccessToPCO`       | `accessPCOYes` | `accessPCONo` | `cfg_communications_t.service_access` (section 7.2) | top-key `5`, sub-field `12`               |
| `TJA100BasicSetup.WppDedicated`            | `False`  | `True`           | `cfg_main_t.wpp_dedicated`                            | top-key `2`, sub-field `8`                |
| `cfg_comm_flags_t.wpp_lock` (packed)       | `False`  | `True`           | `cfg_communications_t.flags` bit `4`                  | top-key `5`, sub-field `0`, bit `4` (RMW) |
| per-row `cfg_arc_t.service_access`         | n/a      | policy-gated     | `cfg_arc_t.service_access`                            | top-key `17`, row, sub-field `15`         |
| `TJA100GSMCom.SIMLock`                     | `False`  | `True` (derived) | UI-only - derived from `wpp_dedicated` + SDC radio    | (no direct address)                       |

`SIMLock` is **not** a distinct persisted field in the embedded schema. It is a
derived F-Link UI lock surfaced when `SDC=True`, `SimPredefined=gspSdc`,
`DisableOperatorSwitch=True`, and `WppDedicated=True`. Clearing `wpp_dedicated` (step
3 below) is therefore the intended way to unlock the SIM/GSM pages, not overriding
the radio-policy fields while the SDC SIM is physically inserted.

Operator playbook (apply one step at a time with a `pull-live` and `fdb_tool.py info`
snapshot before and after each step):

1. **Unlock the top-level communicator gate.**
   `python3 jablotron_arc_tool.py set-live --mode full` - already proven safe on
   2026-03-21. Reversible via `--mode off` (default) or `--mode read`.
2. **If some ARC rows still show read-only in F-Link after step 1**, apply the per-row
   patch `{17: {<row>: {15: 0}}}`. No dedicated helper yet; extension point is an
   additional subcommand in `jablotron_arc_tool.py`.
3. **If the Basic Setup / SIM / SMS pages remain hidden**, clear `wpp_dedicated` with
   `{2: {8: 0}}`. Encode it with `import_cfg_tool.encode_sector`, verify the encoded
   sector with `export_cfg_tool.extract_catalog` (only sub-field 8 of top-key 2 should
   change), then apply via `live_import_apply.py`.
4. **Only as a last resort**, clear `wpp_lock`. This is a bit field inside the 16-bit
   `cfg_comm_flags_t` struct at top-key `5`, sub-field `0`; it requires a
   read-modify-write of the whole flags word. `extract-communications` now decodes
   that word by name so the pre-read is straightforward.
5. **Do not touch** `AESKey`, `YTUNKey`, `RFKey`, any `cfg_arc_*_specific_t.crypt_key`,
   or `cfg_ytun_rsa_key_t`. These are the encrypted ARC-link materials and are marked
   `nemelo by se vubec exportovat nejlepe` in the schema; overwriting them will break
   the ARC link until it is re-keyed. Also leave `SDC`, `SimPredefined`,
   `DisableOperatorSwitch`, `APN`, and `OperatorName` alone on VO-66 while the
   Jablotron SDC SIM is physically inserted - those are radio-policy fields, and a
   mismatch will force the panel into a reconfig loop against the SDC backend.

Full diff, per-field rationale, and non-privilege-relevant deltas (connection-type
routing, SMS reporting policy, failed-arm reporting, annual service reminder, forwarding
targets, EditEnabled user counts):
[`notes/2026-04-23_peskova-vs-vo66-service-access-diff.txt`](notes/2026-04-23_peskova-vs-vo66-service-access-diff.txt).

### 7.4 Exported crypto material

The saved VO-66 export sample
(`research/exports/2026-03-07_live-service_EXPORT.CFG.bin`) demonstrates that
`EXPORT.CFG` can carry live ARC/reporting encryption keys and related endpoints -
these are not just high-level labels:

- Collection `0x11` correlates directly with `cfg_arc_t`. The top-level field order
  matches exactly: `type`, `transfers_on`, `contest_in_fixed_time`, `backup`,
  `backup_test_reports`, `object_id[]`, `err_wait_time`, `report_time`,
  `report_time_backup`, `retry_count`, `time_out`, `channel`, `comment`, `specific`,
  `ats_class`, `service_access`. Nested field `13` matches `cfg_arc_specific_t` and
  its protocol-specific children in order: `sia_ip`, `sia_cid`, `sia_fsk`,
  `jablo_ip`, `jablo_sms`, `jablo_img`, `device`. `channel = 0` follows the schema
  note `0 == automatic`.
- `specific.0.9 = "AES-default-key"` matches
  `cfg_arc_sia_ip_specific_t.crypt_key` / `SIAEncryptionKey`.
- `specific.3.5 = "evgo%^TOarc"` matches
  `cfg_arc_jablo_ip_specific_t.crypt_key` / `JabloIPEncryptionKey`.
- `specific.5.3 = "ABCD"` matches
  `cfg_arc_jablo_img_specific_t.crypt_key` / `JabloIMGEncryptionKey`.
- Observed endpoints `194.169.224.113:10488`, `194.169.224.114:10488`, and
  `194.169.224.113:10470` line up with the ARC-protocol `Domain` / `Domain1` fields.

In addition, `extract-communications` surfaces the communicator-side secrets that are
present in-band: `aes_key_ascii`, `aes_key_hex`, `ytun_key`, `rf_key_ascii`,
`rf_key_hex`. These supersede the earlier note that communicator-side secrets were
not yet extractable.

Still not recovered from saved exports so far:

- `cfg_data_t.ytun_rsa_key` (`cfg_ytun_rsa_key_t.key`) - not mapped to a recurring
  readable collection yet; schema flags it as special-access with the comment
  `nemelo by se vubec exportovat nejlepe`.
- Per-peripheral RF crypto material / rolling-code seeds. The peripherals appear in
  the object/hardware side of the export (`0x09`, `0x0B`) and in some compact
  auxiliary tables (`0x0A`, `0x0F`, `0x10`), but none of those currently look like
  per-device RF keys.
- `WPPDomain` has not been recovered from the current exports.

### 7.5 Fields that are persisted but not surfaced as first-class F-Link UI fields

The schema contains stored knobs whose `flrecname` is blank or missing, i.e. they do
not directly appear as first-class exported/imported properties in the normal F-Link
UI layer but are persisted by the panel:

- `cfg_main_t.wpp_dedicated`, `cfg_main_t.simple_log`.
- `cfg_system_t.tm_auto_arm`, `cfg_system_t.gps_latit_longit`,
  `cfg_system_t.sunrise_correction`, `cfg_system_t.sunset_correction`,
  `cfg_system_t.night_mode_periphery`.
- `cfg_system_flags_t.weekend_house`, `fault_bypass_selfresetable`, `fault_alarm_ack`,
  `timezone_unset`, `ant_lost_cause_tamper`, `maintenance_forbidden`.
- `cfg_comm_flags_t.gsm_autoconfig_disabled`, `send_sms_on_failed_arm`.

And the software-only / FL-only classes:

- `cfg_data_t.ytun_rsa_key` - special-access key material.
- `cfg_periphery_setup_t.data` - raw `InternalSetup` blob handled via
  `prf_setup_internal_hook`.
- `cfg_flink_scratch_t` / `cfg_flink_registration_t` - F-Link / portal scratch and
  registration data (`LoginID`, contact name/phone, email, address, GPS, GSM phone,
  hotline, attempts).
- Communicator / ARC `service_access` fields - documented in the schema as FL-only
  access-control flags (`0=yes / 1=no / 2=read only`).

### 7.6 Unauthenticated metadata leak

`jablotron_noauth_probe.py` confirms a limited unauthenticated read over HID without
sending any authorisation code: model, hardware version, firmware version,
registration code, installation name, and section/PG state packets are recoverable.

The same probe does **not** populate `EXPORT.CFG`. Direct O_DIRECT reads after the
unauthenticated trigger still return an all-zero 1 MiB blob, so the current evidence
does not support pre-auth reading of the full config or user table.

---

## 8. Event memory path

`jablotron_event_tool.py` is the operator-facing path into `TfrmJA100EventsMemory`.

- `FLEXI_LOG` exposes `FLEXILOG.TXT`, `FLEXILOG.OLD`, and `LOGINDEX.BIN`.
- F-Link treats the history as one logical archive spanning `FLEXILOG.OLD +
  FLEXILOG.TXT` (capture-era sizes `85131264 + 10512762 = 95644026`,
  matching the decoded logs' `Assumed total LOG file size 95644026 B`).
- `LOGINDEX.BIN` is a sequence of 16-byte records, each two little-endian
  `(timestamp, offset)` pairs. Offsets are in the combined `OLD+TXT` coordinate space.
- On this panel, the indexed `FLEXI_LOG` bytes only become readable while an
  authenticated setup-mode session is active. Mounted reads outside setup mode can
  return zero-fill at the indexed offsets.
- Details and transport choices: `jablotron_event_tool.py pull-live` supports both
  `--transport archive` (stable; keeps setup mode active and reads the physical tail)
  and `--transport direct` (validated at least once on 2026-03-11 but intermittently
  returns `5C 03/09` open failures on this panel).
- Operator-facing `recent` defaults to `--transport archive` plus
  `--end-mode physical` because `LOGINDEX.BIN` can lag far behind the physical tail
  (2026-03-12 live runs all ended at stale logical offset `95758528`).
- For full-history acquisition, `pull-full` reads the entire combined
  `FLEXILOG.OLD+FLEXILOG.TXT` archive from offset `0`. The archive files are
  fixed-size preallocated blobs, so the real content is whatever comes before the
  zero tail; `pull-full` reports `populated_bytes`, `last_nonzero_offset`, and
  `trailing_zero_bytes` and trims the zero tail by default. This typically
  recovers months more history than the F-Link events-memory UI ever displays. On
  this panel a single full pull recovered ~9 months of continuous events
  (2024-06-19 through 2025-03-07, 157,668 `EVENT` records plus 311,054 `INFO`
  records, in ~33 MB of populated archive bytes out of ~99 MB of preallocated
  FLEXILOG.OLD+FLEXILOG.TXT file space).
- To browse the pulled archive after the fact, `jablotron_event_tool.py show`
  renders decoded records as a colorized table (kind/code/keyword-based styling
  with CZ/SK localization, pretty-printed `YYYY-MM-DD HH:MM:SS` timestamps, and
  optional `--group-by-day` banners). It accepts the pulled JSONL directly
  (`--records ...records.jsonl`), a saved archive window (`--archive ...bin
  --metadata ...json`), or a copied files directory (`--files-dir`). Filters
  include `--since`/`--until`, `--grep`, `--events-only`, `--kinds`/
  `--exclude-kinds`, `--limit`, and `--reverse`. Output is `--format pretty`
  (default), `plain`, `tsv`, or `json`; color mode follows `--color auto|always|
  never` plus the usual `NO_COLOR` / `FORCE_COLOR` env variables.

Payload decoding:

- Archive bytes are **not** strong encryption. The `BRev` payload records are
  cumulative-sum encoded and then rendered through F-Link's compact mixed alphabet.
- The decoder is a two-stage transform: cumulative-sum reversal first, then the mixed
  alphabet where `P..Y` act as compact digits only in standalone numeric tokens (not
  inside words such as `Src`, `Spojenie`). Ambiguous `0x41..0x5A` bytes resolve with a
  token-aware case rule: tokens with explicit lowercase later generally decode
  lowercase except for the first letter after title separators (`:`, `(`, `-`, `\`,
  `,`); tokens without lowercase evidence stay uppercase.
- Event texts come from exact code maps or `.fdb` dictionaries first, and
  source/channel cleanup prefers exact normalised aliases plus ID-based `.fdb`
  resolution instead of global fuzzy matching.

`jablotron_event_tool.py` builds its main live decoder catalog from `EXPORT.CFG`, not
just the user table. `--source-export-cfg` resolves user slots, numeric `source_id`
object labels, numeric channel IDs, PG on/off event names, and section display IDs.
Concrete resolutions observed from the saved archive (without `.fdb`):
`Src:259 -> LAN communicator`, `Chnl:44 -> 44: RFID čítačka VO`,
`Src:69 / Chnl:43 -> Periféria 43: DO MB / 43: DO MB`, PG events such as
`59 -> PG 9: BRANKA VO Zap.`. With a full export, section labels such as
`Sect:1 -> 1: SUTEREN` also resolve.

`.fdb` is now optional enrichment rather than the main path for common labels. The
merge order is `.fdb` first, then `EXPORT.CFG`; current live export labels win on
collisions. `.fdb` still fills gaps when a newer auto-pulled `EXPORT.CFG` is missing
the earliest section records.

Remaining decoder weakness: long free-form `INFO(DEVICE, ...)` strings where no `.fdb`
/ export structure exists to snap against.

Workflow background: [`notes/2026-03-10_events-memory-workflow.txt`](notes/2026-03-10_events-memory-workflow.txt).

Panel event-log sample:
`research/exports/2026-03-08_panel-event-log.csv` confirms the user-visible event names
aligned with successful USB applies (`Zmena konfigurácie` plus
`Created backup configuration`) and failed probes (`Neplatná autorizace`).

---

## 9. F-Link configuration-mode background traffic

`sections_states ... 0x94` is **not** a generic failure; it signals
"configuration-active" while another F-Link owns the config channels. The stronger
"another F-Link already owns config channels" signal is `73 09 ... 94 A0 00`, and the
failing F-Link trace logs `All config channels in use flag set` immediately after
that packet. Captures and decoded logs:

- `research/traces/f_link_logs/2026-03-25_baseline-login-exit-without-changes/comm.log.htm`
- `research/traces/f_link_logs/2026-03-25_configuration-in-use-on-login/comm.log.htm`
- `research/captures/usb/f_link/2026-03-25_baseline-login-exit-without-changes.pcapng`
- `research/captures/usb/f_link/2026-03-25_configuration-in-use-on-login.pcapng`
- Decoded text in `research/exports/f_link_comm_logs_{html,text}/`
- Interpretation: [`notes/2026-03-25_configuration-mode-signal.txt`](notes/2026-03-25_configuration-mode-signal.txt)

First-pass map of the steady-state configuration-mode traffic (2026-03-29 traces):

- `52 01 02` - transport/session keepalive.
- `80 01 02` and `80 01 02 52 01 0E 72 01 00` - periodic liveness/status polls while
  config mode is active.
- `52 02 28 <id>` plus `52 .. A8 <id> ...` - main per-object/peripheral live-state
  query/reply family.
- `94 02 <id> ...`, `96 03 ...`, `96 04 ... 6A 01 <subcode>`, and `90 ... 6B ...` -
  layered detail/diagnostic reads.

Full notes:
[`notes/2026-03-29_f-link-config-mode-keepalive.txt`](notes/2026-03-29_f-link-config-mode-keepalive.txt) and
[`notes/2026-03-29_f-link-background-traffic-first-pass.txt`](notes/2026-03-29_f-link-background-traffic-first-pass.txt).

---

## 10. Tooling reference

Top-level scripts (all in the repo root):

- **`jablotron_re_tools.py`** - shared live-panel plumbing: device discovery,
  setup-mode entry, staging, accept, verification. Used by `export_cfg_tool.py`,
  `live_import_apply.py`, `jablotron_user_tool.py`, `jablotron_arc_tool.py`,
  `jablotron_event_tool.py`, and the `dev_test.py` smoke test.
- **`jablotron_usb_debug.py`** - low-level HID replay. Commands:
  `send-raw-report`, `trigger-export`, `f-link-export-session`, plus `--login-first`,
  `--no-reset`, `--response-timeout`.
- **`flexi_pcap_tool.py`** - capture analysis: list SCSI reads/writes, dump/diff
  frames, reconstruct logical files, XOR view.
- **`export_cfg_tool.py`** - decode / pull `EXPORT.CFG`. Subcommands:
  `pull-live`, `extract-users` (`--user-mode dedupe|raw`), `extract-catalog`,
  `extract-arcs`, `extract-communications`, `extract-time-limits`, `dump-text`,
  `dump-readable`.
- **`import_cfg_tool.py`** - decode / build `IMPORT.CFG` sectors. Subcommands:
  `decode-frame`, `build-user-upsert`, `build-user-delete`. Round-trips every captured
  add / edit / delete byte-for-byte. Treats `pg_access` as four `uint32_t` masks so
  `--pgs 1..128` is fully supported (older builds used four 16-bit masks).
- **`live_import_apply.py`** - reusable write path: setup-mode entry, staging,
  unmount, import accept, optional export verification, remount, post-write cleanup
  (`write_cleanup_mode=auto|none|exit-only|login-exit`).
- **`jablotron_user_tool.py`** - operator-facing user CRUD. Subcommands:
  `pull-export`, `list`, `get`, `add`, `edit`, `delete`. `edit` seeds the upsert
  payload from the current `EXPORT.CFG` record so captured templates are no longer
  required. Two-step verification by default (embedded verify export plus an immediate
  authoritative refetch). Preflight validation rejects duplicate code, duplicate
  card, or `time_limited_group_raw > 0` without a code unless
  `--no-preflight-validation` is used. `get` / `list` print raw-record diagnostics so
  duplicate raw hits are visible without re-running in `--user-mode raw`.
- **`jablotron_arc_tool.py`** - communicator-side service-access gate. Subcommands:
  `build-sector`, `set-live` (both with `--mode full|off|read`).
- **`jablotron_event_tool.py`** - events memory. Subcommands: `recent`, `pull-live`
  (`--transport archive|direct`, `--full`), `pull-full` (convenience wrapper that
  pulls the whole FLEXILOG.OLD+FLEXILOG.TXT archive, auto-strips the preallocated
  zero tail, and reports `populated_bytes` / `last_nonzero_offset` so it is clear
  how much of the preallocated archive actually contains events), `show` (render
  decoded history as a colorized, user-friendly table with `--since`/`--until`
  date filters, `--grep`, `--events-only`, `--kinds`/`--exclude-kinds`,
  `--group-by-day`, `--reverse`, and `--format pretty|plain|tsv|json`; honors
  `NO_COLOR` / `FORCE_COLOR`), `extract-records` (`--decode`, `--display-format
  table|tsv|json`), `align-export`, `dump-index`.
- **`f_link_user_tool.py`** - authoritative user extraction from F-Link process
  dumps (`list-snapshots`, `extract-users`, `diff-users`).
- **`f_link_schema_tool.py`** - embedded schema handling. Subcommands: `extract`,
  `show`, `access-report`, `dev-comments`.
- **`f_link_i18n_tool.py`** - F-Link translation catalogues. Subcommands:
  `extract`, `show`, `search`, `list`, `info`, `diff` (supports both `.lng` tree and
  `--from-dump` source).
- **`f_link_comm_log_tool.py`** - decode `TObfuscatedLogStream` comm logs.
  Subcommands: `decode`, `dump-text`, `decode-tree`, `dump-text-tree`.
- **`fdb_tool.py`** - ODBO-Link `.fdb` container. Subcommands: `info`, `unpack`,
  `pack`, `extract-users`.
- **`enum_rtti_scan.py`**, **`property_rtti_correlation.py`** - Delphi RTTI recovery
  and `.fdb` property correlation.
- **`jablotron_noauth_probe.py`** - probe the unauthenticated metadata leak.
- **`dev_test.py`** - small live-path smoke test (the legacy Home Assistant
  `dev_test.py` was moved to `legacy/dev_test_homeassistant_legacy.py`).

### 10.1 Useful commands

```bash
# F-Link user-dump decoding
python3 f_link_user_tool.py list-snapshots research/traces/process_memory/f-link-edit-user-USER91TEST.dmp
python3 f_link_user_tool.py extract-users   research/traces/process_memory/f-link-edit-user-USER91TEST.dmp --format tsv
python3 f_link_user_tool.py diff-users      research/traces/process_memory/f-link-delete-user-USER91TEST.dmp \
                                            research/traces/process_memory/f-link-edit-user-USER91TEST.dmp

# EXPORT.CFG decoding
python3 export_cfg_tool.py extract-users    research/exports/2026-03-07_live-service_EXPORT.CFG.bin --format tsv
python3 export_cfg_tool.py extract-catalog  research/exports/2026-03-07_live-service_EXPORT.CFG.bin --format summary
python3 export_cfg_tool.py extract-arcs     research/exports/2026-03-07_live-service_EXPORT.CFG.bin --format summary
python3 export_cfg_tool.py extract-communications research/exports/2026-03-07_live-service_EXPORT.CFG.bin
python3 export_cfg_tool.py extract-time-limits research/exports/2026-03-07_live-service_EXPORT.CFG.bin --format summary
python3 export_cfg_tool.py pull-live        research/exports/live_EXPORT.CFG.bin --extract-users

# Operator user CRUD
python3 jablotron_user_tool.py list
python3 jablotron_user_tool.py get 88
python3 jablotron_user_tool.py add    89 --name testuser89
python3 jablotron_user_tool.py edit   88 --comment 'Renamed from CLI'
python3 jablotron_user_tool.py delete 89

# Events memory
python3 jablotron_event_tool.py recent --auth-code 1812
python3 jablotron_event_tool.py recent --auth-code 1812 --events-only
python3 jablotron_event_tool.py recent --auth-code 1812 --exclude-kinds INFO
python3 jablotron_event_tool.py recent --transport archive --format tsv --limit 30
python3 jablotron_event_tool.py pull-live      /tmp/live_events_archive.bin --records-output /tmp/live_events_records.jsonl
# Pull the entire retained FLEXILOG.OLD+FLEXILOG.TXT archive at once (goes well beyond
# what the F-Link UI shows; typically back to whenever the panel last rotated its log).
python3 jablotron_event_tool.py pull-full /tmp/full_events/archive.bin \
    --copy-files-dir /tmp/full_events/files \
    --records-output /tmp/full_events/records.jsonl --decode-records
# Render the pulled history as a colorized, paginated table (pipe to `less -R`
# to scroll colors). Supports date / regex / kind filters and day grouping.
python3 jablotron_event_tool.py show --records /tmp/full_events/records.jsonl \
    --events-only --group-by-day --reverse | less -R
python3 jablotron_event_tool.py show --records /tmp/full_events/records.jsonl \
    --since 2024-11-01 --until 2025-01-31 --grep 'poplach|alarm|sabot'
python3 jablotron_event_tool.py show --files-dir /tmp/full_events/files --events-only --format tsv \
    > /tmp/full_events/events.tsv
python3 jablotron_event_tool.py extract-records /tmp/live_events_archive.bin --metadata /tmp/live_events_archive.bin.json \
                                               --source-export-cfg research/exports/2026-03-07_live-service_EXPORT.CFG.bin \
                                               --decode --display-format tsv
python3 jablotron_event_tool.py dump-index /tmp/live_events_files/LOGINDEX.BIN

# IMPORT.CFG / write path
python3 import_cfg_tool.py decode-frame research/captures/usb/f_link/f-link-edit-user-USER91TEST.pcapng 1787 --format json
python3 import_cfg_tool.py build-user-upsert /tmp/user91-edit.bin --user-id 91 --name USER91TEST --code 9999 \
    --card1 0000000012200717 --comment 'THIS IS A SAMPLE USER91TEST NOTE' --permissions-raw 811 \
    --sections-mask 63 --pg-masks 65535,0,0,0
python3 import_cfg_tool.py build-user-upsert /tmp/user90-pg128.bin --user-id 90 --name PG128TEST \
    --pgs 1,32,33,64,65,96,97,128
python3 import_cfg_tool.py build-user-delete /tmp/user91-delete.bin --user-id 91

# FDB / schema / i18n / RTTI / comm logs
python3 fdb_tool.py info          research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb
python3 fdb_tool.py extract-users research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb --format table
python3 fdb_tool.py unpack        research/fdb/after/VO-66_after-edit-user-USER91TEST.fdb /tmp/edit-user.xml --xml-only
python3 f_link_schema_tool.py extract      research/traces/process_memory/f-link-schema-access-system-minidump.dmp research/exports/f-link-embedded-schema.json
python3 f_link_schema_tool.py show         research/exports/2026-03-08_f-link-embedded-schema.json 'MODULE(cfg_storage_types).cfg_communications_t.class.service_access'
python3 f_link_schema_tool.py dev-comments research/exports/2026-03-08_f-link-embedded-schema.json --search service_access
python3 f_link_i18n_tool.py extract 'research/data ingest/F-Link 2.9.2.1509/Languages' research/exports/f-link-i18n-catalog.json
python3 f_link_i18n_tool.py show    research/exports/2026-04-23_f-link-i18n-catalog.json cfg.ja100.systemparams.warndefaultcodes --locale EN --locale CS
python3 enum_rtti_scan.py scan research/traces/process_memory/*.dmp --dedupe --keyword System --keyword Service --keyword Permission --keyword Authorization --keyword Access
python3 property_rtti_correlation.py correlate research/fdb/after/*.fdb --dumps research/traces/process_memory/*.dmp \
    --only-matched --keyword Permissions --keyword TimeLimitGroup --keyword PGAccess --keyword Sections
python3 jablotron_noauth_probe.py probe --read-export --export-output research/exports/noauth_probe_EXPORT.CFG.bin
python3 f_link_comm_log_tool.py decode-tree    research/traces/f_link_logs/roaming_Jablotron_FLink research/exports/f_link_comm_logs_html
python3 f_link_comm_log_tool.py dump-text-tree research/traces/f_link_logs/roaming_Jablotron_FLink research/exports/f_link_comm_logs_text
```

---

## 11. Live-write confidence matrix (2026-03-17)

From the completed live matrix rooted at `/tmp/2026-03-17_175208_live-user-followup/`
(baseline `/tmp/2026-03-17_initial_probe_EXPORT.CFG.bin`), every slot except `89`
returned to baseline cleanly.

Proven safe **reads and writes**:
`name`, `phone`, `code`, `card1` / RFID, `comment`, blocked/enabled via `flags_raw` bit
0, logging suppression via `flags_raw` bit 1, `access` / competence (`access_raw`),
`section_access`, `pg_access`, `time_limited_group`.

Proven safe **single-field partial edits with unrelated fields preserved** (slots and
shapes from the completed matrix):

| Slot | Field           | Shape                                               |
| ---- | --------------- | --------------------------------------------------- |
| 90   | name            | `--name`                                            |
| 95   | phone           | `--phone`                                           |
| 96   | code            | `--pin`                                             |
| 97   | card1           | `--card1`                                           |
| 87   | comment         | `--comment`                                         |
| 91   | blocked/enabled | `--flags-raw 1`                                     |
| 92   | logging         | `--flags-raw 2`                                     |
| 87   | access raw      | `--access-raw 811` (sections and PGs preserved)     |
| 93   | time-limit bind | `--time-limited-group-raw 2`                        |

Proven section-rights edits: add one section (`90`: `{1} -> {1,2}`); remove one
(`87`: `{2,4,6} -> {2,6}`); sparse (`94: {1,8,15}`); contiguous range
(`90: {4,5,6,7}`); clear all (`94: {}` via `--sections-mask 0`).

Proven PG-rights edits (all four `uint32_t` masks): add one
(`95: {1} -> {1,2}`); remove one
(`88: {6,7,8,9,10,11,12,13,14} -> {6,7,8,10,11,12,13,14}`); sparse boundary set
(`99: {1,32,33,64,65,96,97,128}`); clear all (`98: {}` via `--pg-masks 0,0,0,0`).

Proven preservation behaviour: changing sections on `87` preserved PGs
`{2,4,7,10,12,14,16}`; changing PGs on `87` preserved sections `{2,4,6}`; changing
`access_raw` on `87` preserved both; mixed partial edits
(`comment+sections`, `name+sections`, `phone+PGs`, `blocked+comment`) only changed the
requested fields; no-op writes for `sections`, `name`, and `PGs` produced no verified
drift.

Decoded but not yet exercised for intentional writes:
`card2`, `pg_num_if_ring`, `parent_user_no`.

Remaining ambiguous case: slot `89` is the only remaining drift in
`/tmp/2026-03-17_175208_live-user-followup/final_drift.json`. A rollback from a
populated full-update state back to a minimal baseline kept the old
phone / code / card / comment / access / PG / time-limit values while sections
correctly returned to `{3,4,5}`. This is a live panel behaviour question, not a
reproducible CLI encoder bug. Treat slot `89` as unsafe for
rollback-to-minimal until the behaviour is understood from fresh baseline evidence.

Operator-facing reproductions:

```bash
# Baseline pull
python3 jablotron_user_tool.py pull-export /tmp/live_test_EXPORT.CFG.bin --auth-code 1812

# Full update (matches slot 80 in the completed matrix)
python3 jablotron_user_tool.py edit 80 --auth-code 1812 \
    --export-cfg /tmp/2026-03-17_initial_probe_EXPORT.CFG.bin \
    --name 'User80 Full' --phone +421900000080 --pin 8080 --card1 0000000080000080 \
    --comment 'Full update 80' --flags-raw 2 --access-raw 811 \
    --sections 1,3,5 --pgs 1,32,33,64,65,96,97,128 --time-limited-group-raw 2

# Sections-only preservation on slot 87
python3 jablotron_user_tool.py edit 87 --auth-code 1812 \
    --export-cfg /tmp/2026-03-17_initial_probe_EXPORT.CFG.bin --sections 1,5,15

# PG-only preservation on slot 87
python3 jablotron_user_tool.py edit 87 --auth-code 1812 \
    --export-cfg /tmp/2026-03-17_initial_probe_EXPORT.CFG.bin --pgs 1,32,33,64,65,96,97,128

# Metadata-only preservation on slot 87
python3 jablotron_user_tool.py edit 87 --auth-code 1812 \
    --export-cfg /tmp/2026-03-17_initial_probe_EXPORT.CFG.bin --comment rights-preserve87

# Boundary PG example on slot 99
python3 jablotron_user_tool.py edit 99 --auth-code 1812 \
    --export-cfg /tmp/2026-03-17_initial_probe_EXPORT.CFG.bin --pgs 1,32,33,64,65,96,97,128
```

Full matrix detail, blocker, and tooling fixes that the run exposed:
[`notes/2026-03-17_live-user-edit-campaign-blocker.txt`](notes/2026-03-17_live-user-edit-campaign-blocker.txt).

---

## 12. Operational tips

- Memory dumps contain stale heap fragments - use `f_link_user_tool.py` to pick a
  coherent `JA100UsersSetup` / `TJA100AllUsers` snapshot rather than grepping loose
  strings across the whole dump.
- The latest complete snapshots in the current edit/delete dumps resolve the
  authoritative state of user `91` correctly - populated in the edit session, empty /
  default in the delete session.
- Refreshed exports can contain a ghost copy of the just-added user near the end of
  the blob (observed once after adding user `88`). Summaries should dedupe by user ID;
  `jablotron_user_tool.py` does so by default (`--user-mode dedupe`) but also offers
  `--user-mode raw` for reverse-engineering when repeated record-shaped hits matter.
- Direct O_DIRECT reads of `IMPORT.CFG` sector 0 after a successful apply can snap
  back to older payloads (for example `USB3`) even when `EXPORT.CFG` reflects the new
  value. Always verify from a fresh `EXPORT.CFG` pull.
- Prefer `sudo mount` / `sudo umount` / `sudo dd` over `udisksctl` on this host - the
  latter may block on a desktop polkit prompt.
- F-Link command-line logging: `F-Link.exe -commlog` rotates `comm.log.htm` /
  `comm.log.1.htm` / ... under `%APPDATA%\Jablotron\FLink\`. Captured comm log
  folders are available under `research/traces/f_link_logs/`.

---

## 13. Document history

- **2026-04-23** - comprehensive reverse-engineering documentation pass.
  Reorganised the README from a chronological journal into indexed sections;
  removed obsolete claims ("`cfg_communications_t` not decodable from `EXPORT.CFG`",
  "communicator-side secrets not recovered", "`cfg_comm_flags_t` bitfields not
  surfaced by extract-catalog" - all of those are now decoded by
  `export_cfg_tool.py extract-catalog` / `extract-communications`); added the
  EXPORT.CFG top-key table (section 3.3), the `cfg_user_t` field / rights-label
  tables (section 3.4), the `cfg_comm_flags_t` bit table (section 3.5), and the
  Peskova-vs-VO-66 delta table (section 7.3); published the embedded-schema
  dev-comments (372 entries) and F-Link i18n catalogues (23 locales, 4141 keys per
  locale) under `research/exports/`; added `f_link_schema_tool.py dev-comments` and
  `f_link_i18n_tool.py`.
- **2026-04-23** - Peskova reference backup compared against VO-66; per-field sparse
  addresses and operator playbook in
  [`notes/2026-04-23_peskova-vs-vo66-service-access-diff.txt`](notes/2026-04-23_peskova-vs-vo66-service-access-diff.txt).
- **2026-03-29** - first-pass map of the steady-state configuration-mode background
  traffic.
- **2026-03-25** - `sections_states ... 0x94` identified as "configuration-active",
  and `73 09 ... 94 A0 00` as the "config channels in use" signal.
- **2026-03-21** - live proof that `{5: {12: 0}}` unlocks ARC/PCO editing in F-Link
  for a plain service session; wrapped in `jablotron_arc_tool.py`.
- **2026-03-17** - completed live user-edit matrix on slots `80-99`; slot `89`
  rollback-to-minimal remains the sole open semantic blocker. Tooling fixes landed
  the same day in `jablotron_re_tools.py` (`stage_import` sudo fallback,
  `pull_live_export_snapshot` unmount-before-read,
  `dedupe_user_records` latest-offset, `apply_import_sector` verify-retry).
- **2026-03-11/12** - events memory acquisition and decoding; archive transport is
  the stable path; decoder is a two-stage cumulative-sum + compact-alphabet transform
  with a token-aware case rule; `LOGINDEX.BIN` can lag far behind the physical tail.
- **2026-03-10** - setup-mode handshake reconstructed; live add / edit / delete of
  user `86` (`TESTUSERWALDO`) verified; `live_import_apply.py` packaged; second-session
  HID cleanup pattern adopted for both read and write flows; user tooling refactored
  (`jablotron_user_tool.py` added; legacy HA `dev_test.py` moved).
- **2026-03-08** - first live semantic user edit succeeded (`TESTUSERWALDO` comment
  `Waldo has a new comment -> USB8` persisted across repeated fresh pulls); embedded
  schema extracted; comm-log `TObfuscatedLogStream` decoded.
- **2026-03-07** - USB protocol breakthrough (`EXPORT.CFG` live refresh, XOR+MessagePack
  decoding, cache-free direct block read). Full report in
  [`2026-03-07_usb-protocol-research-report.md`](2026-03-07_usb-protocol-research-report.md).
