# Handoff: user records longer than one HID report (2026-10-03)

The HID `0x1D` user write (see `docs/handoff-2026-09-25-write-gate.md`,
"Decoded" and "Implemented") is live-proven for records that fit one 64-byte
report. The first real record the owner's board tried to provision did not fit:

```
add_user failed: token=board-provisioning-write (...) resource=user:33
reason=Panel write failed: Configuration payload of 124 bytes does not fit one
HID report (at most 60); how F-Link splits larger records is not captured yet.
POST /v1/users HTTP/1.1" 409 Conflict
```

The owner then captured F-Link doing exactly that. This document says what the
capture shows and what is left to build.

## Owner's note, verbatim

> Okay, you can find a new capture in "research/data ingest". one note
> though. the failed write was me putting in definitely way more characters
> into the notefield than 60. Comm log answers it: F-Link sends one TLV
> `1D FA ...` (length byte 0xFA = 250) wrapped in the 48/49/4A chunk framing.
> Checking exact chunk shape on the wire, headers only.

The "failed write" is F-Link's own form validation at 02:24:32 (`MessageBox
shown: There are errors in the window, you have to correct them first!`). It
never reached the panel.

## Evidence (private, never commit, never upload)

- `research/data ingest/flink-longrecord.zip` (gitignored folder): the
  owner's bundle. Unpacked in `.git/claude-scratch/flink-longrecord/`:
  `capture-long-record.pcapng` (USBPcap, 02:20:02-02:34:00 local),
  `flink-logs/comm.log.htm` and its decode `comm.log.htm.txt`
  (`f_link_comm_log_tool.py dump-text`), `hid-host-to-panel.txt`,
  `hid-panel-to-host.txt`, `timeline.txt`, `SUMMARY.txt`,
  `windows-events.txt`, and `flow.txt` = `hid_flow_tool.py` output (both
  directions, TLV-decoded, one line per report).
- Contents are sensitive: the master code, the slot-96 test user's code,
  card and phone, and, because F-Link batched them into the first save, the
  full records of two real users (positions 6 and 78: names, phones, cards).
  Quote framing bytes and lengths in docs and tests, never field values.
- Session: F-Link 2.9.2.1509 on the Windows VM, master-rights login,
  `LoggedPosition: 100`. IMPORT.CFG untouched for the whole session, as in
  the 2026-09-25 master session.

## What the capture shows

### Long-message framing (host to panel and panel to host alike)

A TLV packet longer than one report is carried in chunk packets:

| chunk | bytes | carries |
| --- | --- | --- |
| first | `48 3E <count> <61 data bytes>` | `count` = total number of chunks including this one |
| middle | `49 3E <62 data bytes>` | repeated as needed |
| last | `4A <len> <len data bytes>` | the remainder, 4 to 59 bytes in the captures |

Concatenating the data bytes gives one ordinary TLV packet
`<type> <len> <data...>`. Verified on every chunked message in the capture
(`flow.txt` frames in brackets):

| direction | inner TLV | len byte | real data length | chunks | count byte |
| --- | --- | --- | --- | --- | --- |
| H>P [915] F-Link logon info | `A0 7D 03 "Info(0):--F-Link ..."` | 0x7D = 125 | 125 | 3 | 3 |
| H>P [6333] SAVE 1 | `1D FA 09 00 <msgpack>` | 0xFA = 250 | 397 | 7 | 7 |
| H>P [9475] SAVE 2 | `1D FA 09 00 <msgpack>` | 0xFA = 250 | 324 | 6 | 6 |
| H>P [12581] SAVE 3 | `1D C6 09 00 <msgpack>` | 0xC6 = 198 | 198 | 4 | 4 |
| P>H [1132, 7869] reply to `52 2B` | `52 FA A9 ...` | 0xFA | 304 | 5 | 5 |
| P>H [2245, ...] device table | `90 EF ...` | 0xEF = 239 | 239 | 4 | 4 |

So: the length byte is the real length up to 250; anything longer carries
`0xFA` and the receiver takes the length from the chunk framing. The
same rule holds for the panel's own long replies. The chunk count byte is
exactly the number of chunks, nothing else. F-Link sends chunks about 2 ms
apart, the keepalive `52 01 02` continues between messages, and the panel
answers a chunked `1D` with the same single `1D 03 44 00 00` as a short one
(comm log lines 1586, 2610, 3135: 0.3 s, 0.3 s and 15 ms after the last
chunk).

### The three saves

- SAVE 1 (02:25:49) wrote three user records in one `{7: {...}}` map:
  positions 6, 78 and 96. F-Link flushes every record it considers dirty,
  not just the edited slot. The panel accepted it. Configuration revision
  check: not read in this session; the revision query `52 03 1A 01 00`
  appears in F-Link's traffic as usual.
- SAVE 2 (02:28:14, 60-character comment) was acked by the panel at
  02:28:15. F-Link then ran its post-write reload and reported
  `Communication error: No answer to request, ReqType: JA107_RELOAD_CFG`
  at 02:30:24 (comm log 2915-2921) and showed "Communication error". The
  record was written; the export rebuild afterwards did not answer. This is
  the same symptom as our `embedded verification export did not reach the
  reload-complete state; retrying (1/3)` after both live HID writes on
  2026-10-03 01:54. It is a panel-side behaviour after a write, not a
  chunking problem.
- SAVE 3 (02:31:58, shorter comment, slot 96 only): 198-byte inner TLV,
  4 chunks, acked. Delete (02:32:54): single report `1D 07 09 00 81 07 81 60
  C0`, acked.

### Record encoding, as before

The msgpack inside is the IMPORT.CFG sector command: `{7: {position:
{0..11}}}`, several positions per map allowed. Non-ASCII names are UTF-8
(`C3 A1`, `C4 8D` in the capture). `import_cfg_tool.pack_msgpack` produces
these bytes already; the 60-byte cap was ours, not the panel's.

### Side finding: our logon-info string is malformed

F-Link's first chunk is `48 3E 03 A0 7D 03 "Info(0):--F-Link ..."`: the
inner TLV has type `0xA0`, a length byte and a sub-type `0x03` before the
text. Ours (`jablotron_usb_debug.build_flink_info_log_reports`) sends
`48 3E 03 "Info(0):..."` with no inner header. The panel tolerates it. Fix
the framing when touching this, and replace the `F-Link 2.9.2.1509`
identity with this project's own name: it is written into the panel's log
and misleads anyone reading it. Check live that the panel accepts an
arbitrary string.

## Code state

- Branch `reverse-engineering` at `f5c8c00` (pushed). HID write path:
  `jablotron_re_tools.write_config_over_hid`,
  `build_hid_config_write_packet` (raises the 409 text above when the
  payload exceeds `HID_CONFIG_WRITE_MAX_PAYLOAD` = 60),
  `apply_config_payload_over_hid`, `apply_sector`,
  `probe_login_rights`; transport selection in
  `src/jablotron_api/services/user_manager.py` (`select_write_transport`,
  `JABLOTRON_PANEL_WRITE_TRANSPORT`). Tests: `tests/test_hid_config_write.py`.
- Live-proven 01:54-01:58: slot 96 add and delete over HID from the host CLI
  (`docs/api-server-refactor-status.md`, 2026-10-03 entry).
- The API container is not running. `.env` still sets
  `JABLOTRON_PANEL_WRITE_AUTH_CODE` (the ARC-rights code), which makes
  `auto` pick the storage path; comment it out before deploying the HID
  path. The owner's board (`board-provisioning-write` token) will retry
  user 33 as soon as the API accepts long records.

## What to build

1. **Chunked send.** In `jablotron_re_tools.py`, replace
   `build_hid_config_write_packet` with a builder that returns the list of
   64-byte reports to send: inner = `1D <len> 09 00 <msgpack>` where
   `len = min(len(data), 0xFA)` and `data = 09 00 <msgpack>`; if the inner
   packet fits one report, send it alone as today; otherwise split into
   `48 3E <count>` + 61 bytes, `49 3E` + 62 bytes each, `4A <rest_len>` +
   rest, zero-padded to 64, and send them back to back through
   `perform_send_raw_report` (it already sleeps 0.1 s per write; F-Link's
   2 ms spacing is not a requirement we know of, but keep the chunks
   contiguous, no keepalive in between). Keep awaiting `1D 03 44 00 00`.
   Raise the size cap to something generous (the IMPORT sector allowed
   510 bytes of command; 1024 is safe) with the same clear message.
   `write_config_over_hid` and `apply_config_payload_over_hid` keep their
   signatures, so `user_manager` and the CLI need no change.
2. **Tests, without the private data.** Rebuild the framing from synthetic
   records of the same sizes (198, 324, 397 data bytes) and assert count
   byte, chunk lengths, `0xFA` cap and the single-report case. Compare
   against the real capture only in a throwaway script under
   `.git/claude-scratch/flink-longrecord/` (for example: load the H>P
   `48/49/4A` groups from `flow.txt`, reassemble, check that your builder
   splits the reassembled inner packet back into the identical chunk
   sequence). Do not paste names, phones, cards or codes from the capture
   into the repo. The slot-96 test user in SAVE 3 is also the owner's data;
   treat it the same.
3. **Panel-side long replies.** The same framing carries the device table
   (`90 EF`) and the `52 2B` reply. Check whether the diagnostics code in
   `src/jablotron_api/protocol/legacy.py` or `jablotron_re_tools.py`
   reassembles `48/49/4A` today; if it only reads single reports it silently
   drops long replies. Not needed for the write ack.
4. **Logon-info framing and identity** (side finding above).
5. **Post-write export stall.** Both our live writes and F-Link's SAVE 2 saw
   the first export rebuild after a write not finish. Ours retries after 2 s
   and succeeds; F-Link gave up and showed an error. Consider a short wait
   (1-2 s) before the first verification export, then measure whether the
   retry disappears. Keep the retry.
6. **Deploy and prove.** Comment out `JABLOTRON_PANEL_WRITE_AUTH_CODE` in
   `.env`, `docker compose up -d --build`, check the startup line says
   `use the auto transport`, then `POST /v1/users` for a record over 60
   bytes (user 33 from the board, or slot 96 with a long comment through
   the client CLI), confirm `Write code logged in with master rights
   (position 100); using the hid transport.` in the container log and the
   record in `GET /v1/users/<id>`. Capture with
   `sudo -n tshark -i usbmon9 -w /tmp/<name>.pcapng` (writing under `~`
   failed as root), decode with `hid_flow_tool.py`, and compare the chunk
   sequence with frames 12581-12587 of the F-Link capture.

## Rules that apply

- Live writes only on slot 96 (and the owner's own user 33 request through
  the board), delete afterwards, fresh export before and after. Never arm
  or disarm anything but section 5 (RACK); PG tests only on 6, 7, 8, 9, 15;
  at most two wrong-code attempts per session, wrong codes very different
  from real ones.
- Stop the container (`docker compose stop jablotron-api`) before any host
  CLI session on `/dev/hidraw0`; two sessions on the device split replies
  and log each other out.
- No panel code in committed files, logs, or messages. Compare for
  equality only.
- Write the session summary into `docs/api-server-refactor-status.md`
  (new dated block under "Progress Log"), not only here.
