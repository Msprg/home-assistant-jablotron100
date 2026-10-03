# Handoff: configuration operations inside the status session (2026-10-03)

Where the in-session refactor stands, what the first live run showed, and
what the next agent has to do. Companion to the status entry of the same
date in `docs/api-server-refactor-status.md` and to the earlier handoffs
`docs/handoff-2026-10-03-long-hid-writes.md` (chunked HID write, now
superseded for the server path) and `docs/handoff-2026-09-25-write-gate.md`.

**Resolved later the same day.** The warm session had lost its authorisation
(the panel pushes `80 01 01` about 57 s after a login). The operations now log
in again on the open channel first (`ff2b26d`), and the slot 96 proof passed
with the switch on. Result and numbers: the status entry "in-session
operations proven live on slot 96" in `docs/api-server-refactor-status.md`.
The steps under "What to do next" are done except for the open items listed
there. The rules below still apply.

## Rules first

- The live JA-107K is attached to this host. On 2026-10-03 the test suite
  reached it through an unpatched cleanup path and tripped the tamper alarm
  (`119 Neplatná autorizace` x18, then `149` and `23 Sabotáž`; see the
  incident entry in the status doc). `tests/conftest.py` now refuses every
  device open and every `dd`/`mount` subprocess during tests and fails a
  test that provoked a refusal. Never set `JABLOTRON_ALLOW_HARDWARE_TESTS`.
  Never let an agent, workflow or loop run anything but the pytest command.
- Live tests only on slot 96, container stopped before any host CLI
  session, at most two wrong codes per session, pull the panel events
  (`jablotron_api_client_tool.py events recent`) after any long run and
  look for `119`.
- No panel code values in files, logs or messages. The usbmon captures
  contain the login packet; they stay in `.git/claude-scratch/`.

## State

- Branch `reverse-engineering` at `e86a5b7`, pushed. Commits of this work,
  in order: `3eb5802` (phase 1: HID write inside the session), `3fa0fe9` +
  `b8ed3c8` (test hardware guard), `accf0f4` (phase 2: export trigger inside
  the session), `16d12a4` (phase 3: one export pull per write, dirty cache),
  `fa81743` (phase 4: login rights from the session, docs), `e86a5b7`
  (final-review fixes). Suite: 481 passing with the guard active.
- Design spec the implementers followed, with per-field rationale and the
  review log: `/home/administrator/.claude/jobs/467fab81/tmp/spec.md`
  (job temp dir; copy it somewhere durable if you want to keep it, the
  status entry carries the decisions).
- Container `home-assistant-jablotron100-jablotron-api-1` runs image
  `40040c57` (tree `e86a5b7`) **with the kill switch on**:
  `JABLOTRON_PANEL_IN_SESSION_CONFIG_OPS=false` in `.env`, so writes and
  catalog pulls use the old separate-client path. `.env` also has
  `JABLOTRON_PANEL_WRITE_AUTH_CODE` commented out (auto transport probes the
  master code and writes over HID). The local `docker-compose.yml` forwards
  the two new knobs.
- Main checkout is behind; pull it from a separate terminal (the worktree
  session may not run git there).

## What the first live run showed (04:56 UTC, capture in `.git/claude-scratch/in-session-proof/`)

`POST /v1/users` for slot 96 with the in-session path on returned
`409 Panel catalog read failed: Export refresh did not reach the
reload-complete state.` after 11 s. No write was attempted. Sequence on the
wire, from the status session that had been logged in since 04:53 with
device states enabled (times are panel-local, UTC+2):

```
06:56:09.110 H>P 80 01 0F              -> P>H 80 02 1B 03   (not the 80 02 1A 0A a fresh login gets)
06:56:09.314 H>P 52 02 13 05 9A 00     -> P>H 52 03 82 FD 13 (refused)
06:56:09.416 H>P 48/49/4A logon-info line
06:56:09.722 H>P 52 01 25              -> P>H 52 03 82 FD 25 (refused; no 52 07 83 01 25 ever)
06:56:17.8   bounce: 94 02 01 00, 80 01 01 52 01 0E, 52 01 02, then fresh login
06:56:19.077 H>P 52 02 13 05 9A 00     -> P>H 52 03 82 01 13 (accepted, on the fresh login)
```

Reading: `52 03 82 FD <cmd>` is the panel refusing a command, `52 03 82 01
<cmd>` accepting it. The export refresh sequence (`JA107_RELOAD_CFG` shape:
`80 01 0F`, `52 02 13 05 9A 00`, logon line, `52 01 25`) is refused on a
long-lived status session and accepted right after a fresh login. The
`80 01 0F` reply `80 02 1B 03` instead of `80 02 1A 0A` is the first sign.
Every proven export trigger and every proven write so far ran within about
two seconds of a login. The preflight pull was taken because the catalog in
cache came from startup (older than the 60 s window); the single preflight
attempt has no retry by design, so the write never started.

The status WebSocket topic (poll snapshots every 2.5 s) showed one 11.95 s
gap during the operation, the asyncio lock blocking the poll while the
trigger waited 8 s and bounced. Stream edges would have passed through the
tee; none occurred.

Earlier the same day the first in-session catalog pull may have worked: the
`GET /v1/users` at 04:56:01 returned in a few seconds, but the capture shows
no trigger for it, so it was served from the startup cache. Treat the
in-session trigger as unproven.

## What to do next

1. **Make the in-session export trigger start from a fresh login.** In
   `PersistentSnapshotSession.trigger_export` (`src/jablotron_api/protocol/legacy.py`)
   bounce with reopen before `send_flink_export_refresh_sequence`, the way
   the spec's original 0.2 rule had it, or find what the warm session lacks
   (candidates: the `0x13` device-state subscription, the 240 s keepalive
   state, the `80 01 0F` already answered earlier). The capture gives one
   data point: the same session got `82 01` three seconds after a fresh
   login. Keep `finish_export` as it is.
2. **Expect the same for the write.** `write_configuration` sends `80 01 0F`
   from the warm session too (with `assume_logged_in=True`). It was never
   reached live. The spec's open question 1 (fresh login immediately before
   `80 01 0F`) now looks like the answer; `BOUNCE_AFTER_SUCCESSFUL_WRITE`
   handles the end of the write, a matching "bounce before" is needed at the
   start. The `_await_login_rights_locked` + `SETUP_MODE_NUDGE_DELAY` wait
   from `e86a5b7` already covers the timing after that login.
3. **Decide whether the preflight pull should retry like the post-write one**
   (`reload_retries`), or whether a fresh-login trigger makes the single
   attempt reliable. Measure, then decide.
4. Rebuild, set `JABLOTRON_PANEL_IN_SESSION_CONFIG_OPS=true`, repeat the
   live run: `users list` (fills the cache), `users create 96` with a
   comment under 60 bytes but a record over 60 msgpack bytes, `users delete
   96`, under `sudo -n tshark -i usbmon9 -w /tmp/<name>.pcapng` and the
   status WebSocket watcher (`ws --topic status`, run with
   `PYTHONUNBUFFERED=1`; the token needs `sections:read pgs:read
   devices:read`). Success means: the chunk reports `48 3E 02 1D ... / 4A`,
   the ack `1D 03 44 00 00`, `52 03 83 01 02`, `80 01 17`, no login packet
   between the first `80 01 0F` and the `80 01 17` (or exactly the one
   "bounce before" login if you add it), the record in `GET /v1/users/96`,
   the table back to baseline after the delete, no `119` in the panel
   events, and status frames with no gap above the poll interval plus the
   lock hold.
5. Update the status entry with the result; if the kept channel works for
   the post-write pull, say so, if it needs the bounce, flip the default.

## Tooling left in the job temp dir (`/home/administrator/.claude/jobs/467fab81/tmp/`, gone when the job is deleted)

`api.sh` (client wrapper reading the token from `tok`), `ws_watch.sh`,
`ws_gaps.py`, `summarize_users.py`, `d8_config.py` (lists `d8` pushes and
configuration-mode frames in a `hid_flow_tool.py` flow file),
`compare_chunks.py`, `decode_tables.py`, `events_summary.py`, `spec.md`.
The proof token `0ca0bac3d5ca7d4d` (label `in-session-live-proof`) is
revoked at the end of this session; create a new one with the admin tool.
