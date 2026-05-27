# Jablotron API Server Refactor Status

## v1 lock

The `/v1` REST + WebSocket schema is now locked for the public alpha. The authoritative description lives in `docs/openapi.v1.json`; regenerate with `venv/bin/python -m jablotron_api.cli.main openapi-export docs/openapi.v1.json`. Stability guarantees and the scope vocabulary are documented in the top-of-README "v1 stability promise" section.

Package version: `1.0.0a1` (`src/jablotron_api/__init__.py` and `pyproject.toml`).

## Objective
- Merge the current Home Assistant integration and reverse-engineering work into a maintainable Python API server with a server-backed Home Assistant client integration.

## Architectural Decisions In Force
- Single server process owns one USB-connected panel.
- API transport is `HTTPS` + `WebSocket`.
- mTLS is required at transport startup; app-layer token binding supports an optional certificate fingerprint input for authorization binding.
- REST uses scoped bearer tokens.
- WebSocket topic subscriptions are scope-filtered using the same token scopes as REST routes.
- Panel writes remain serialized through one runtime lock.
- Fresh `EXPORT.CFG` pulls remain the authoritative verification source after writes.
- A `demo` runtime mode exists for container/client/integration smoke tests without panel hardware.

## Workstreams
- [x] Add installable Python package and package layout under `src/jablotron_api/`
- [x] Add SQLite-backed token store and audit log
- [x] Add FastAPI app with `/v1` REST surface and `/v1/ws`
- [x] Add reference Python client
- [x] Add initial `PanelRuntime` built on current RE helpers
- [x] Add demo runtime for container/client smoke tests without hardware
- [ ] Move remaining repo-root business logic fully into package modules
- [x] Complete Home Assistant migration to API-backed runtime with legacy entity/state parity
- [x] Fill out communicator/time-limit export endpoints with full decoded payloads
- [x] Harden client certificate fingerprint extraction for direct ASGI transport instead of header-assisted binding
- [x] Add container files and initial deployment artifacts
- [x] Add initial API/auth/WebSocket tests

## Current File / Module Layout
- `src/jablotron_api/domain/models.py`: stable Pydantic API models
- `src/jablotron_api/protocol/legacy.py`: live HID query/control adapter using existing helpers
- `src/jablotron_api/panel/runtime.py`: cached panel runtime, background polling, export/user/event access
- `src/jablotron_api/panel/demo.py`: in-memory runtime for demo-mode smoke tests
- `src/jablotron_api/services/storage.py`: SQLite token/audit/snapshot store
- `src/jablotron_api/services/auth.py`: scope enforcement helpers
- `src/jablotron_api/server/app.py`: FastAPI application factory and routes
- `src/jablotron_api/server/ws.py`: WebSocket connection manager
- `src/jablotron_api/client/api.py`: reference async client
- `src/jablotron_api/cli/main.py`: server/bootstrap/reference client CLI
- `jablotron100-api-HASS/custom_components/jablotron100_api_hass/`: authoritative HACS-installable API-backed Home Assistant integration under a non-conflicting domain
- `custom_components/jablotron100/`: legacy direct-HID/reference Home Assistant integration retained in the main repo for comparison and historical context
- `Dockerfile`, `docker-compose.yml`: container-first deployment artifacts

## Implemented Endpoints / Features
- `GET /v1/health`
- `GET /v1/system`
- `GET /v1/status`
- `GET /v1/sections`
- `GET /v1/pgs`
- `GET /v1/devices`
- `POST /v1/sections/{id}/arm`
- `POST /v1/sections/{id}/disarm`
- `POST /v1/pgs/{id}/on`
- `POST /v1/pgs/{id}/off`
- `GET /v1/users`
- `GET /v1/users/{id}`
- `POST /v1/users`
- `PATCH /v1/users/{id}`
- `DELETE /v1/users/{id}`
- `GET /v1/events`
- `GET /v1/events/recent`
- `GET /v1/export/users`
- `GET /v1/export/catalog`
- `GET /v1/export/time-limits`
- `GET /v1/export/communications`
- `POST /v1/tokens`
- `GET /v1/tokens`
- `DELETE /v1/tokens/{id}`
- `GET /v1/ws`
- Client-facing status/control/user surfaces now enforce usable initial-setup ranges while raw export endpoints remain unrestricted:
  - `/v1/status`, `/v1/sections`, `/v1/pgs`, `/v1/devices`
  - `/v1/users`, `/v1/users/{id}`, and user CRUD writes
  - section arm/disarm and PG on/off control routes
- `GET /v1/export/catalog` now exposes both:
  - `initial_setup`: exact export-derived limits when available, otherwise documented inferred limits
  - `raw_counts`: full raw catalog breadth for reverse-engineering and low-level tooling

## Remaining Gaps / Known Blockers
- Repo-root reverse-engineering tools are not yet reduced to thin wrappers.
- No known Home Assistant entity/control parity gaps remain against the legacy integration surface; rare hardware now depends on server heuristics plus per-device manual override options in the Home Assistant integration.
- The remaining major validation task is broader live alpha coverage across more panel/device combinations, not a currently known missing parity feature in the integration code.
- The HACS-facing API integration now lives in the `jablotron100-api-HASS` git submodule and is the only maintained API-backed Home Assistant integration codebase; the root `custom_components/jablotron100` tree is legacy/reference only.
- Development/deployment docs now cover a low-friction local mTLS path, but the first real Home Assistant alpha installation against that path still needs to be exercised end to end.

## Testing Status
- Legacy repo tests still existed before the refactor and passed at the start of this implementation pass.
- Added initial API server tests for:
  - health + system routes
  - token-authenticated user CRUD routes
  - WebSocket subscription handshake + snapshot delivery
- Added auth tests for scope denial, token revocation, and certificate-bound tokens.
- Added tests for:
  - export-catalog `initial_setup` and `raw_counts` exposure
  - client-facing range rejection for out-of-range sections, PGs, and users
  - ASGI-scope TLS fingerprint binding on HTTP requests
- Added tests for:
  - exact root-map extraction from `EXPORT.CFG` blobs with trailing data
  - FAT16 export-file discovery and cluster-chain walking for direct live pulls
- Added Home Assistant parity tests for:
  - legacy control ID recreation
  - dynamic central/device diagnostic entity creation
  - wrong-code event forwarding in the API-backed runtime
- Added legacy-parity coverage for:
  - restored thermostat/thermometer state entities
  - restored legacy device-type inference for glass-break / garage-door / valve-style devices
  - Home Assistant-side per-device type overrides, including ignored `other` devices
- Current local result after the latest implementation pass: `75 passed` via `venv/bin/pytest -q`
- Remaining test gaps:
  - runtime integration against mocked RE helper failures
  - Home Assistant integration behavior
  - full live hardware validation on a real panel

## Hardware Validation Status
- Demo-mode validation is now an explicit part of the smoke-test path and does not replace live panel validation.
- Verified the dockerized demo path on 2026-03-24:
  - built `jablotron-api-server:test`
  - generated a local CA, server cert, and client cert
  - ran the container with `JABLOTRON_API_RUNTIME_MODE=demo`
  - created an admin token in the mounted SQLite DB with `jablotron_api_admin_tool.py`
  - confirmed `jablotron_api_client_tool.py system` and `status` over mTLS
  - confirmed control commands `arm 1 --mode away` and `pg-off 2`
  - confirmed `jablotron_api_client_tool.py ws --topic status --topic catalog --count 3`
  - confirmed a request without a client cert failed at the TLS/connection layer
  - confirmed a cert-bound token now succeeds over direct mTLS transport without any manual fingerprint query/header override
- Verified live read-only panel access on 2026-03-24 with the panel connected to `/dev/hidraw0`, `FLEXI_CFG` on `/dev/sdb1`, and `FLEXI_LOG` on `/dev/sdd1`:
  - low-level HID system-info read returned panel model `JA-107K`, hardware `MD6112.09.1`, firmware `MD12007`
  - runtime status read returned 6 section states over USB
  - export refresh + extraction returned a non-empty catalog with 14 sections, 128 PGs, 55 objects/devices, and 102 deduped users
  - runtime recent-events read returned decoded archive records after fixing the event-field mapping bug
  - runtime status now applies export-catalog names to live section and PG state rows, so `/v1/status` and `/v1/export/catalog` agree on names
  - initial-setup usable limits are now exposed and enforced on the live path with inferred values matching the known F-Link export for this panel:
    - sections `6`
    - devices `50`
    - users `100`
    - PG outputs `20`
  - live runtime status is now filtered to those client-facing limits, returning `6` sections, `20` PGs, and `50` device rows while raw export catalog still reports the full `14` / `128` / `55` breadth
  - local live API server run on `https://127.0.0.1:9444` served `system`, `status`, `devices`, and `events` successfully through the thin TLS client wrapper
  - no write/control endpoints were exercised during the live panel validation pass
  - reversed the late export-blob issue and confirmed the root cause was a truncated direct file read rather than an unsupported export variant:
    - `EXPORT.CFG` on the live `FLEXI_CFG` volume starts at the FAT16 data area, sector `34`
    - the old direct-read defaults started at sector `35`, so the first 512-byte sector of the file was dropped
    - when read from the correct start sector, the live export decodes as a normal top-level MessagePack map and `main_config` is present exactly
    - exact live `main_config` values from the connected panel now decode as:
      - users `100`
      - peripheries/devices `50`
      - sections `6`
      - PG outputs `20`
      - language `SK`
      - code length `4`
      - code prefix `False`
      - system name `VO 66`
  - verified a fresh patched live pull with `venv/bin/python export_cfg_tool.py pull-live ...` and confirmed `extract-communications` now returns the exact current `main_config` and communicator data from the live panel
  - verified the richer parity-oriented live snapshot path on the connected panel:
    - central LAN IP is decoded on the live path
    - thermostat/smoke temperatures are decoded on the live path
    - wireless battery level and signal strength values are decoded on the live path
    - the current live panel still does not appear to expose extra central battery/bus data through the same path on `JA-107K`, which matches the practical limits of the earlier integration's model-specific queries
- Runtime operations currently rely on the already proven helpers:
  - live export pulls
  - event archive pulls
  - user CRUD via `IMPORT.CFG` staging + authoritative export verification
  - section and PG control via HID UI packets
- Verified the stale-session cleanup fix on 2026-03-25:
  - stopping the container and waiting roughly 3 minutes before restart produced a clean startup with no `configuration-active (0x94)` warning, proving the earlier warning was stale panel-side session state rather than an unavoidable startup export issue
  - a manual `cleanup_read_session(..., cleanup_mode="exit-only")` run immediately after container stop reached `exited (0x90)` on the live panel without requiring a login-based cleanup fallback
  - the runtime shutdown path was then patched so normal server shutdown now:
    - closes the long-lived `PersistentSnapshotSession`
    - immediately runs `cleanup_read_session(..., cleanup_mode="exit-only")` on a fresh HID handle
  - live proof after the patch:
    - rebuilt the Docker container
    - performed an immediate `docker stop` followed by `docker start`
    - startup completed cleanly with no `configuration-active (0x94)` warning
- Verified the expanded reference client against the connected live panel on 2026-04-26:
  - live server started on `https://127.0.0.1:9446` using the local development mTLS certificates
  - reference client successfully read `health`, `system`, `status`, `devices`, `export-catalog`, `users list`, `users get 90`, and `events recent`
  - live event pulls initially read the archive but returned HTTP 500 because post-read cleanup ended in `0x80`; `jablotron_event_tool.py` now treats that non-configuration cleanup miss as a warning after a successful archive read, matching the existing export-read behavior
  - live user-management writes were intentionally skipped because reserved validation user ID `90` was already occupied by a non-test user
  - live section/PG control was intentionally not exercised in this pass
- Follow-up live user validation on 2026-04-26 after freeing slot `90`:
  - reference client confirmed slot `90` was absent before testing
  - API-backed `POST /v1/users` for slot `90` initially returned `409`
  - lower-level `jablotron_user_tool.py add 90 --name ...` succeeded against the same live panel and authoritative refetch showed user `90`, proving the underlying import primitive still works
  - API-backed `PATCH /v1/users/90` also initially failed verification when attempted against the low-level-created user
  - lower-level `jablotron_user_tool.py delete 90` succeeded afterwards, and a final export confirmed `raw_matches_user90 0`
  - live section/PG control remained intentionally untested
  - the reference client now exposes `--timeout` so live write calls can wait longer than the default 30 seconds
- Follow-up live user validation on 2026-04-27:
  - root cause found in the server add verification path: `UserCreateModel` defaults were being compared as exact requested values, so omitted raw fields such as `flags_raw`, `access_raw`, and `time_limited_group_raw` caused a false `409` after the panel wrote concrete defaults
  - `PanelRuntime._verify_added_user()` now verifies `name` plus only optional fields explicitly supplied by the API caller
  - the server was run against the live panel on `https://127.0.0.1:9447` with `JABLOTRON_PANEL_AUTH_CODE=1812`
  - reference client live user flow passed for reserved slot `90`: absent check, create, patch with `code=9090`, `access_raw=811`, sections `1,2`, PGs `1,2`, read-back verification, delete, and final absent check
  - the panel was left with user `90` absent
- Live Rack/PG 15 control validation on 2026-04-27:
  - the server was run against the live panel on `https://127.0.0.1:9448` with `JABLOTRON_PANEL_AUTH_CODE=1812`
  - initial state was Rack section `5` = `armed_away` and PG `15` = `off`
  - PG `15` was toggled `off -> on -> off` and each state was verified through the API status response
  - Rack section `5` was toggled `armed_away -> disarmed -> armed_away` and each state was verified through the API status response
  - final read-back confirmed Rack section `5` was restored to `armed_away` and PG `15` was restored to `off`

## Latest Decisions / Assumptions
- Use the current proven helper stack first, then progressively internalize logic into the new package.
- Prefer cached export/catalog reads plus periodic live status polling instead of a complex long-lived HID stream in the first server cut.
- Treat F-Link initial-setup limits as a higher-layer client contract rather than a low-level raw-config restriction:
  - raw export endpoints remain full-fidelity
  - client-facing status/control/user endpoints enforce usable ranges
  - Home Assistant consumes the exposed usable-range metadata and ignores raw tail capacity outside that range
- When `main_config` is absent, infer usable ranges pragmatically from catalog structure:
  - sections from real device section assignments
  - devices from contiguous non-system object IDs
  - users from the highest regular user ID below the internal high-ID range
  - PG outputs from the first long all-default suffix in the PG catalog
- Exact export decoding for `main_config` now depends on reading the real `EXPORT.CFG` file bytes from the FAT16 volume instead of assuming a fixed raw sector window.
- Root export-map extraction now uses standard MessagePack unpacking of the first top-level object, which is robust to trailing padding or appended data after the root map.
- Keep the document authoritative for implementation state and next steps.

## Next Recommended Tasks
1. Move the remaining reusable logic from root RE scripts into `src/jablotron_api/`.
2. Add more failure-path tests around runtime/helper exceptions and WebSocket scope denials.
3. Perform Home Assistant alpha testing against the server-backed integration and record any real-world parity gaps here.
4. Decide whether the remaining root-level reverse-engineering CLIs should become thin wrappers or stay as explicitly low-level tooling outside the server package.
5. Add a documented migration step for any users who tested the earlier alpha API runtime with the pre-parity control IDs.
6. Keep future API-backed Home Assistant fixes in the `jablotron100-api-HASS` submodule only; do not mirror them into the root `custom_components/jablotron100` legacy/reference tree.

## Deferred to v1.1

These items from the v1-lock refactor plan were intentionally deferred so the v1 alpha could ship from a known-stable state. They are tracked here so future work picks them up explicitly:

- **A6 — thin root-level CLI wrappers**: `jablotron_user_tool.py`, `jablotron_event_tool.py`, `export_cfg_tool.py`, `import_cfg_tool.py` still own their own argparse surfaces alongside the new `services/user_manager.py`, `services/event_reader.py`, and `services/catalog_io.py`. The service modules are the single source of truth for the mutation logic the API server uses; the root CLIs reuse the same low-level primitives directly. Thinning them further would require lifting their CLI-specific report formatters into the package and was judged not worth the v1-window churn.
- **B2 — split `api_runtime.py`**: the 861-line Home Assistant `api_runtime.py` was kept as one module in v1.0.0a1. The audit found it well-structured; splitting it carries non-trivial risk to entity unique-ID stability for installed users. Targeted cleanup (dead `jablotron.py` removed, platform setup helper, dropped sync entity methods, enum-derived device-type labels) is in. The deeper coordinator/entity-registry/ws-loop split remains on the v1.1 roadmap.

## Planned: Home Assistant Add-on packaging

In addition to the standalone Docker/native server, the API server is intended to ship as a Home Assistant Add-on so users with a single HA OS box can plug the panel USB directly into that box, install the add-on, and connect the integration to it locally — no separate Raspberry Pi or mini-PC needed.

Implications to keep in mind from now on so we do not paint the add-on into a corner:

- **mTLS must remain optional, not mandatory.** When the add-on binds to localhost only (or to HA Supervisor's internal network), mTLS is overkill and a friction multiplier for casual users. `ServerSettings.mtls_required` is currently hardcoded `True`; in the add-on path it needs to be controllable via the add-on options schema (mapped to env). Native/docker paths can keep mTLS-on as their default.
- **Configuration must be env-driven end to end.** HA add-on options are surfaced to the container as `/data/options.json`; the standard pattern is an `run.sh` that reads that file and exports env vars before launching the server. Our current strict-env model (`JABLOTRON_PANEL_AUTH_CODE`, etc.) is the right shape for this; do not add CLI-flag-only knobs that bypass env.
- **Token bootstrap needs an add-on-friendly path.** Today `bootstrap-token` is a separate CLI invocation against the SQLite store. For the add-on, the natural UX is "the add-on prints a startup token on first run" or a small admin endpoint that the integration's config flow can call. The current CLI path stays; the add-on layer should add a startup-token print on its own.
- **USB device exposure**: HA add-on config supports `devices:` and `usb:` declarations. Our existing requirement (`/dev/hidraw*`, plus the FLEXI block devices for export/log pulls) maps to that; no code change needed, but the add-on config.yaml will need to declare them and the user will pick the host devices via the add-on UI.
- **Persistent state at `/data`**: already matches HA add-on conventions (the add-on `/data` directory is the canonical persistent store).
- **Custom repository distribution**: the add-on can be hosted in a separate small repo (e.g. `Msprg/hassio-addon-jablotron-api`) referencing our `jablotron-api-server` Docker image. The add-on Dockerfile typically extends a base image and runs `pip install jablotron-api-server`; this works as soon as we publish the package to PyPI or push the built image to a registry.

No code changes needed right now to support this; the requirements above are forward-looking guardrails so v1.x decisions don't accidentally rule it out.

## Progress Log
### 2026-05-27
- Completed the v1-lock refactor pass on the API server and the HACS integration:
  - **A1** — Extracted `src/jablotron_api/services/{device_inference,catalog_io,event_reader,user_manager}.py` from `PanelRuntime`. The 1211-line runtime became ~500 lines of orchestration with the service modules owning the actual conversion/CRUD/event logic. `_infer_device_type`, `_catalog_to_model`, `_apply_catalog_names`, `_user_to_model` re-exported from `panel.runtime` for test compatibility.
  - **A2** — `PanelRuntime.arm_section` and `disarm_section` collapsed to one `_invoke_section_control` helper. `DemoPanelRuntime`'s three identical `_ensure_usable_*_id` helpers now delegate to `services.catalog_io.ensure_id_in_range`, matching the live runtime.
  - **A3** — `server/app.py` route handlers refactored: introduced `_execute_runtime_call` which collapses the repeated scope-check + log-request + try/except/HTTP-map + audit-write + log-complete block used by arm/disarm/pg_on/pg_off/add_user/edit_user/delete_user. Token-aware serializers moved into `domain/serialization.py`. WebSocket subscribe handshake split into `_handle_ws_subscribe` + `_send_ws_snapshot`.
  - **A4** — Scope vocabulary redesigned as a strict resource:action hierarchy. Breaking changes: `status:read` removed (split into `sections:read`, `pgs:read`, `devices:read`); `sections:control` split into `sections:arm` and `sections:disarm`; `catalog:read OR config:read` alias on `/v1/export/catalog` removed; `codes:impersonate` now applied uniformly across section and PG control whenever the supplied code differs from the server auth code. `TokenStore` runs `migrate_scope_list` once at startup to rewrite legacy tokens in place, logging one warning per token. Migration test verifies a pre-v1 token comes back with the v1 scopes after store re-open.
  - **A5** — `/v1/events/recent` is now a deprecated alias for `/v1/events`. New `openapi-export` CLI subcommand generates `docs/openapi.v1.json`; that file is checked in as the canonical v1 surface description. README gains a "v1 stability promise" paragraph.
  - **B1** — Deleted the dead 2830-line `jablotron.py` from the HACS submodule (pre-API-migration HID/serial protocol code; verified no live module imports it). Trimmed `const.py` to drop ~150 lines of legacy `PACKET_*`/`COMMAND_*`/`UI_CONTROL_*` constants and supporting enums. The `EntityType.POWER_SUPPLY = "power_supple"` string-value typo was deliberately left intact because changing it would break installed entity identity.
  - **B3** — New `platform_setup.py` with `setup_entity_platform(...)` removes boilerplate `add_entities`+`async_dispatcher_connect` blocks from all five platforms. Dropped dead sync `alarm_arm_*`/`alarm_disarm` and `turn_on`/`turn_off` methods now that the async overrides are authoritative. `event.py:trigger_event` uses `async_write_ha_state` to match the rest.
  - **B5** — `DEVICE_TYPE_OPTION_LABELS` in the integration's `config_flow.py` is now generated from the `DeviceType` enum via `get_name()` instead of a hardcoded mirror list.
- Package version bumped to `1.0.0a1` (`pyproject.toml`, `src/jablotron_api/__init__.py`). The HACS submodule manifest version was left at its existing track to preserve update continuity for installed users.
- Test suite expanded from 75 → 77 passing tests; the additions cover the legacy-scope migration and the new strict catalog-read scope enforcement. Compileall passes on the integration package and the server package.
- A6 (thin root-level CLI wrappers) and B2 (deep `api_runtime.py` split) were intentionally deferred to v1.1 — see the "Deferred to v1.1" section above for rationale.
- Live hardware re-validation against the connected JA-107K panel and an end-to-end Home Assistant alpha run against the v1 server are the remaining gates before tagging `v1.0.0` proper.

### 2026-04-27
- Fixed the API-backed live user create verification bug by distinguishing omitted optional create fields from fields explicitly requested by the API caller.
- Added regression coverage for create verification when the panel supplies concrete defaults for omitted raw fields.
- Re-ran live reference-client user management against slot `90`; create, patch, read-back verification, delete, and final absent check passed, with no live section/PG control exercised.
- Re-ran live section/PG control validation during an approved maintenance window: Rack section `5` and PG `15` both changed state successfully and were restored to their original states.

### 2026-04-26
- Expanded the reference API client from a smoke-test wrapper into a full `/v1` operator client:
  - structured non-2xx error handling
  - users/events/export/token/control/WebSocket helpers
  - packaged `jablotron-api-client` entrypoint
  - root `jablotron_api_client_tool.py` retained as a compatibility launcher
- Reduced client CLI drift by delegating packaged server client usage through the shared client CLI module instead of separate `client-status` / `client-users` code paths.
- Fixed demo runtime PG control parity with the live runtime call shape so FastAPI demo-mode PG routes accept the same `code` and token user-binding arguments.
- Added regression coverage for the reference client, CLI payload parsing, and demo-mode PG control.
- Hardened live event-log reads so a successful archive read is not discarded solely because non-configuration cleanup ended in `0x80`.
- Demo smoke validation passed for health/system/status/users/events/export/tokens/WebSocket plus demo user, section, and PG writes.
- Live validation passed for read-only server/client paths and event pulling; user writes were skipped because reserved slot `90` was occupied.
- Follow-up live validation found that API-backed user writes still fail verification for newly freed slot `90`, while the lower-level user tool can add and delete that slot successfully. The panel was left with user `90` absent.

### 2026-03-29
- De-duplicated the Home Assistant integration codebases:
  - removed the duplicated API-backed runtime/client from the root `custom_components/jablotron100` tree
  - restored the root `custom_components/jablotron100` package to a legacy direct-HID/reference role
  - retargeted API-backed Home Assistant tests to the submodule package `custom_components.jablotron100_api_hass`
  - updated docs so the `jablotron100-api-HASS` submodule is the only supported API-backed install/debug path
- Investigated an intermittent live-panel PG control failure where:
  - the API returned `200 OK`
  - the panel never executed the PG action
  - no matching event record appeared in F-Link
  - restarting the API server temporarily restored PG control
- Narrowed the issue to the long-lived HID session in `PersistentSnapshotSession`:
  - steady-state reads kept working because the raw HID session heartbeat stayed alive
  - privileged panel authorization on that same session could silently expire after idle time
  - when that happened, PG/section control packets were sent on a still-open HID handle but were ignored by the panel
  - the previous implementation only refreshed authorization when switching to a different code, not when reusing the same code after idle time
- Refined the fix in `src/jablotron_api/protocol/legacy.py` to avoid reintroducing idle-time authorization noise:
  - the first attempt at a fix refreshed same-code authorization proactively after idle time, which restored PG reliability but also brought back repeated `Autorizácia OK` events on ordinary control actions
  - the current implementation instead keeps the ordinary same-code path quiet and treats stale authorization as a retryable miss
  - PG control now:
    - sends the control packet on the existing long-lived HID session
    - actively requests section/PG state once
    - waits briefly for PG-related confirmation packets (`ui_toggle_pg_output` or `pg_outputs_states`)
    - only if no confirmation arrives does it refresh authorization once and retry the PG action
  - if the retry still produces no panel confirmation, the server now raises an error instead of returning a false `200 OK`
  - switched-code actions still use the existing explicit auth-end + auth-code path
- Added focused regression coverage for:
  - retrying PG control with one forced auth refresh after a missing confirmation
  - not refreshing authorization when PG control is confirmed on the first attempt
  - preserving the existing single-login/no-reopen behavior for ordinary control calls
- Validation:
  - `venv/bin/pytest -q tests/test_api_server.py tests/test_api_runtime_parity.py` -> `43 passed`
  - `venv/bin/pytest -q` -> `53 passed`
- Remaining live validation:
  - retest the previously reproduced scenario on the real panel:
    1. fresh server start
    2. one successful PG toggle
    3. wait a few minutes
    4. second PG toggle
  - expected result now: the second action should execute normally, with a single refreshed authorization if the session was idle long enough

### 2026-03-25
- Fixed API-backed Home Assistant `problem` binary sensors showing `unknown` for most devices:
  - server-side `DeviceStatusModel.problem` now defaults to `False` instead of `None`
  - the HACS integration runtime now seeds newly created section-problem, device-problem, and fire entities with `STATE_OFF` so they do not sit in `unknown` while waiting for a later state packet
  - focused validation:
    - `venv/bin/pytest -q tests/test_api_server.py tests/test_jablotron_re_tools.py` -> `19 passed`
    - `python3 -m compileall jablotron100-api-HASS/custom_components/jablotron100_api_hass src/jablotron_api/domain/models.py` passed
- Tightened status responsiveness without turning every cycle into a full device sweep:
  - `PanelRuntimeConfig.poll_interval_seconds` now defaults to `2.0s` instead of `15.0s`
  - added `full_refresh_interval_seconds` (default `15.0s`) so sections/PGs refresh quickly while full device-info sweeps remain slower
  - added `fast_status_timeout_seconds` (default `0.6s`) and `full_status_timeout_seconds` (default `2.0s`)
  - `PersistentSnapshotSession.query_snapshot(...)` now supports a lightweight mode that only requests section/PG state and reuses any already-streamed device packets, instead of sending full per-device info requests every cycle
  - `PanelRuntime.refresh_status()` now runs:
    - fast lightweight section/PG polls every `2s`
    - full device-info refresh every `15s`
    - diagnostics refresh every `1h`
  - practical effect: Home Assistant and API clients should see section arm/disarm and PG changes much faster, without the server hammering every device-info query at 1-2 second cadence
- Reverse-engineered the "system already in configuration" signal from two new F-Link traces dropped into `research/data ingest/` and sorted them into the permanent research layout:
  - raw comm logs moved to `research/traces/f_link_logs/2026-03-25_*`
  - matching USB captures moved to `research/captures/usb/f_link/2026-03-25_*.pcapng`
  - decoded HTML/plaintext exports written to `research/exports/f_link_comm_logs_html/` and `research/exports/f_link_comm_logs_text/`
  - findings recorded in `research/notes/2026-03-25_configuration-mode-signal.txt`
- Confirmed from the paired traces that:
  - `sections_states ... 0x94` means configuration-active, not a generic failure
  - the stronger "another F-Link/configuration session already owns setup mode" indicator is the `73 09 ... 94 A0 00` state packet
  - F-Link logs this same condition as `All config channels in use flag set`
- Updated `jablotron_re_tools.py` accordingly:
  - setup-mode entry now raises a dedicated "system already in configuration mode" error instead of falling through to `Did not enter setup mode.`
  - post-read cleanup now treats `0x94` as a known configuration-active state instead of a generic dirty exit
  - automatic cleanup no longer falls through to the noisy `login-exit` retry when the panel is already reporting configuration-active/in-use
  - export-pull warnings now mention configuration-active state explicitly instead of claiming an unknown unclean exit
- Updated `jablotron_event_tool.py` so event-session cleanup reports the same configuration-in-use condition consistently.
- Added focused regression tests around:
  - `0x94` / `73 09 ... 94 A0 00` detection
  - runtime shutdown running `exit-only` cleanup after closing the persistent HID session
- Fixed server-side stale USB session handling across container restarts:
  - `PanelRuntime.close()` now remembers whether a persistent status session existed, closes it, and then runs the low-level `exit-only` cleanup helper on a fresh HID connection before process exit
  - this preserves the no-extra-auth steady-state behavior while still clearing the panel-side session state that previously survived rapid container restarts
  - focused validation:
    - `venv/bin/pytest -q` -> `33 passed`
    - live container stop/start with no multi-minute wait now comes back cleanly, with no startup `configuration-active (0x94)` warning
- Investigated missing thermostat diagnostics on the live panel:
  - direct live captures showed wireless thermostats `JA-150TP` do return temperature over HID, but their packets arrive later than the earlier per-device diagnostics window and often only after initial ack/status packets
  - server changes in `src/jablotron_api/protocol/legacy.py` now:
    - keep reading through quiet gaps during diagnostics instead of stopping after the first empty read
    - use a longer diagnostics timeout for wireless thermometers/thermostats
    - prepend a direct `device_info` request before each diagnostics force-info request
    - prioritize unresolved wireless temperature devices first in the diagnostics sweep
  - runtime changes in `src/jablotron_api/panel/runtime.py` now retry diagnostics after `60s` instead of `1h` when any wireless thermometer/thermostat is still missing temperature
  - Home Assistant runtime changes now remove stale dynamic battery/signal/temperature entities when the current API payload no longer supports them, which should clean up wired thermostats that had orphaned battery entities from older runs
  - focused live validation:
    - manual single-device HID queries confirmed both wireless thermostats can return temperature packets on this panel
    - live API runs after intermediate patches alternated between resolving one or the other wireless thermostat temperature, which is why the final reliability-oriented prioritization/retry patch was added
  - setup-mode conflict classification
  - cleanup short-circuiting before a fallback re-login when configuration is already active
- Verification:
  - `venv/bin/pytest -q tests/test_jablotron_re_tools.py tests/test_api_server.py` -> `17 passed`
  - `python3 -m compileall jablotron_re_tools.py jablotron_event_tool.py` passed

### 2026-03-24
- Added the initial installable `jablotron_api` package, FastAPI app, WebSocket manager, SQLite token store, reference client, CLI, and first `PanelRuntime`.
- Chose a pragmatic first server cut that wraps existing proven RE helpers instead of fully relocating all logic immediately.
- Recorded the current limitation around certificate fingerprint extraction for direct ASGI transport; transport-level mTLS is intended, but app-layer fingerprint binding still needs server-level peer-cert plumbing.
- Added container build/deploy artifacts and initial FastAPI route/WebSocket tests.
- Migrated the Home Assistant integration to a first API-backed runtime without removing the legacy HID-oriented module used by the low-level reverse-engineering tools.
- Verified the repo test suite after the refactor: `venv/bin/pytest -q` completed with `6 passed`.
- Added a packaged demo runtime so the docker image, mTLS wiring, client wrappers, and Home Assistant integration can be smoke-tested without a live panel.
- Expanded the reference client and thin wrappers to support mTLS certificates on both REST and WebSocket connections, plus control-oriented alpha-test commands.
- Tightened WebSocket authorization so topic subscriptions are filtered by token scopes and catalog snapshots use a dedicated `catalog` topic instead of overloading `system`.
- Updated the Home Assistant API runtime to consume catalog-driven section/PG/device names directly, so section and peripheral naming no longer depends on manual generic setup.
- Completed a real dockerized smoke test of the demo runtime with generated mTLS material and the root wrapper tools; the next missing validation step is live hardware testing against a real panel and Home Assistant alpha testing against that server.
- Performed a live read-only validation pass against the connected panel and found/fixed two concrete runtime issues: export catalog refresh reliability on the live path and decoded recent-event field mapping.
- Finished catalog-name unification so live status rows now reuse export-derived section and PG names instead of generic placeholders.
- Implemented initial-setup aware client-facing limits:
  - `ExportCatalogModel` now exposes `initial_setup` and `raw_counts`
  - `PanelRuntime` now filters status/users/control operations to usable ranges while keeping `/v1/export/*` raw
  - Home Assistant catalog consumption now respects those usable ranges instead of blindly creating entities for raw tail capacity
- Investigated the live export and confirmed that `main_config` is still `None` for the current panel/export variant, so the first implementation uses a documented inference fallback instead of pretending the limits were decoded exactly.
- Verified on the live connected panel that the inferred usable limits match the known F-Link values (`6` sections, `50` devices, `100` users, `20` PG outputs) and that filtered runtime status now returns exactly `6` sections, `20` PGs, and `50` devices.
- Verified the full local test suite after the initial-setup implementation: `venv/bin/pytest -q` completed with `10 passed`.
- Added direct transport-aware TLS fingerprint extraction by running the bundled server with custom Uvicorn protocol classes that inject the client certificate fingerprint into ASGI scope for both HTTP and WebSocket.
- Verified that a cert-bound token now authenticates successfully over the real demo-mode TLS server without the previous manual fingerprint parameter.
- Reversed the late export-blob issue and confirmed the live panel was not producing a special unsupported export format; the direct-read path was simply omitting the first sector of `EXPORT.CFG`.
- Added FAT16-based `EXPORT.CFG` discovery and exact file reading for live direct pulls, with fallback to the previous raw-sector method only if the filesystem-based path fails.
- Switched root export-map extraction to standard MessagePack unpacking of the first top-level object so valid exports still decode even if trailing bytes remain after the root map.
- Verified against the connected live panel that a fresh patched pull now decodes `main_config` exactly, including `users=100`, `peripheries=50`, `sections=6`, `pgs=20`, `language=SK`, `code_len=4`, and `name='VO 66'`.
- Added focused regression tests for root export extraction and FAT16 export-file discovery/cluster walking, and verified the suite at `11 passed`.
- Completed the API-backed Home Assistant parity pass:
  - restored legacy control IDs such as `section_1`, `device_sensor_2`, `device_problem_sensor_2`, `pulses_4`, `lan`, and `gsm_signal_sensor`
  - recreated the legacy entity surface from API data, including central-unit sensors, device problem sensors, wireless signal/battery sensors, temperature sensors, pulse sensors, and wrong-code event forwarding
  - added optional user-supplied code forwarding on section arm/disarm API calls so the API-backed integration can surface `wrong_code` behavior again
  - expanded the server status model to carry per-device diagnostic fields plus central-unit LAN/GSM/power/bus data where the panel path exposes them
- Verified the richer live snapshot path against the connected panel: real thermostat/smoke temperatures, wireless battery levels, wireless signal strengths, and LAN IP are now decoded through the server-side parity path.
- Fixed a packaging regression in the new legacy adapter so the server can still be imported by the system Python without requiring the full Home Assistant package to be installed globally.
- Added parity-focused tests and verified the suite at `16 passed`.
- Moved the API-backed Home Assistant integration into the prepared `jablotron100-api-HASS` git submodule as a HACS-ready package:
  - new installable domain: `jablotron100_api_hass`
  - new visible integration name: `jablotron100-api-HASS`
  - added submodule-root `hacs.json` and `README.md`
  - updated manifest metadata and UI titles so it can be installed alongside the original `jablotron100` integration without a domain clash
- Added development-only mTLS onboarding files:
  - `scripts/generate-dev-certs.sh` now generates a local CA plus server/client certs with SANs for localhost, detected host IPs, and any extra `--ip` / `--dns` values
  - `docker-compose.dev.yml` mounts `.dev-certs` and `.dev-data` for a low-friction local alpha path
  - `docs/dev-mtls.md` documents the exact IP-vs-hostname rule for certificate SANs and the Home Assistant config values to use
- Fixed the container entrypoint environment so `/app` is on `PYTHONPATH`; this keeps the current packaged server able to import the still-root-level helper modules during dockerized dev and alpha testing.
- Fixed the reference Python client to build one explicit SSL context for HTTPS as well as WebSocket connections, which avoids the earlier `httpx` mTLS disconnect on the local development path.
- Fixed the Home Assistant API runtime control path to use thread-safe `hass.add_job(...)` scheduling for section and PG control calls invoked from executor-backed entity methods, removing the `hass.async_create_task` cross-thread runtime error during arm/disarm and PG toggles.
- Hardened two more Home Assistant runtime boundaries in the API-backed integration:
  - `_send_signal_entities_added()` now tolerates being called without a running loop in the current thread and reschedules dispatcher delivery onto the HA loop
  - `_trigger_wrong_code()` now reschedules event-entity updates and bus firing onto the HA loop if ever called from a non-loop thread
- Corrected the section-number/name bridge between raw export metadata and live HID status/control:
  - live HID section IDs are 1-based human/F-Link numbers
  - export section records are zero-based
  - the server now renames live status sections using `display_id + 1`
  - the Home Assistant API runtime now builds section entities and smoke/fire associations using human section numbers derived from `display_id + 1`
- Fixed a Home Assistant startup regression in the HACS-facing integration:
  - the long-lived WebSocket receive loop was previously started with `hass.async_create_task(...)` during entry initialization
  - Home Assistant treated that task as part of startup and logged `Setup timed out for bootstrap waiting on <Jablotron._ws_loop()>`
  - the integration now starts the WebSocket loop with `config_entry.async_create_background_task(...)` after the initial REST bootstrap completes, so startup is no longer blocked by the forever-running push task
- Fixed severe live-panel event-log pollution from the API server status poller:
  - root cause: every `refresh_status()` opened a fresh HID client, sent `perform_login(...)`, queried status, sent `perform_logout(...)`, and closed the HID handle
  - with the default `15s` poll interval this produced repeated `Spojenie nadviazané` / `Spojenie ukončené` and `Autorizácia OK` events multiple times per minute
  - reverse-engineering review plus live probing showed that a privileged read session can be kept alive without resending the service code by maintaining the HID handle and sending raw `52 01 02` keepalive packets
  - the server now uses a persistent `PersistentSnapshotSession` for steady-state status polling:
    - one HID login when the status session is first created
    - raw `52 01 02` keepalive every second
    - device-state broadcast renewal before the 5-minute timeout lapses
    - no `perform_logout(...)` after each status refresh
  - export pulls, event archive reads, control actions, and write/apply flows now explicitly close that persistent read session first so their one-shot HID helpers do not fight over the same device
  - focused regression coverage now checks that repeated snapshot queries reuse the same authenticated session instead of performing a second login
  - live verification on 2026-03-25:
    - a direct wrapped `PersistentSnapshotSession` against `/dev/hidraw0` performed two real status queries `35s` apart with `login_calls == 1`
    - the rebuilt dockerized live server still served `/v1/system` and `/v1/status` successfully after the change
- Added a dedicated Home Assistant control-code path for client-triggered control actions:
  - the API-backed Home Assistant integration now exposes an optional `Default control code` in the options flow
  - when set, section arm/disarm and PG on/off requests initiated from Home Assistant include that code explicitly in the REST request
  - the API server now accepts an optional `code` query parameter on `POST /v1/pgs/{id}/on` and `POST /v1/pgs/{id}/off`, matching the existing section-control behavior
  - the panel runtime uses the supplied action code for that control request instead of always falling back to the server-wide panel auth code
  - this makes Home Assistant-originated user actions attributable to the Home Assistant code path instead of being indistinguishable from background server operations that still rely on the server auth code
  - regression coverage now checks that the supplied code is forwarded from the REST layer into the panel runtime for section arm, section disarm, and PG control
- Reduced extra authorisation churn on control actions by reusing the persistent HID session for section and PG commands:
  - root cause: section arm/disarm and PG control previously closed the persistent read session, opened a fresh HID client, logged in, sent the control packet, logged out, and then forced the status poller to log in again
  - the persistent HID session now supports in-session section and PG control directly on the already-open handle
  - when the requested control code matches the session’s current authorised code, the server now sends the control packet directly with no extra login or session restart
  - when the requested control code differs, the server now switches authorisation in-session instead of tearing the HID handle down and reopening it
  - if an in-session code switch fails, the session attempts to restore the previous authorisation and otherwise drops the handle cleanly so the next read starts from a known-good state
  - focused regression coverage now checks that:
    - same-code control actions reuse the same HID client and the original login
    - different-code control actions switch codes without reopening the HID device or performing a second `perform_login(...)`
- Reduced boot-time authorisation noise from the server startup path:
  - likely root cause of the observed `3-4` standalone `User 100: HomeAssistant -> Autorizácia OK` events on container boot:
    - startup did a one-shot privileged `refresh_system()`
    - startup then did a separate privileged export/catalog pull
    - startup then created the persistent status session with another privileged login
    - the catalog pull can retry once on an empty first read, which explains the occasional fourth auth event
  - the persistent HID session now supports system-info queries on the already-open handle
  - startup ordering is now:
    - export/catalog pull first
    - system-info query on the persistent HID session
    - status snapshot on that same persistent HID session
  - `/v1/system` no longer forces a fresh privileged system-info poll on every request once system info is already cached from startup
  - focused regression coverage now checks that system-info queries and snapshot queries can share the same HID client and original login
- Investigated unavailable central-unit entities in the API-backed Home Assistant integration (`Power supply`, `GSM signal`, `GSM signal strength`) on the live JA-107K panel:
  - live API probing showed this was not a Home Assistant availability bug; the server was returning `None` for those central fields
  - direct packet dumps confirmed:
    - the current JA-107K diagnostics path does return LAN info for device `233`
    - it does not currently return central power/battery info for device `0` through the known request sequence
    - GSM diagnostics for device `234` arrive as `DeviceInfoType.UNKNOWN_GSM (21)` rather than the already-decoded `DeviceInfoType.GSM (4)`
  - the Home Assistant API runtime now follows the stricter client behavior chosen during testing:
    - `Power supply`, `GSM signal`, and `GSM signal strength` are not created at all unless `/v1/status` carries real non-`None` values for them
    - if older registry entries for those controls already exist from a previous build, the runtime removes them during startup rather than leaving them behind as `unavailable`
  - `LAN connection` remains available because the live JA-107K path does decode it reliably
  - exact JA-107K decoding for central power and `UNKNOWN_GSM` remains a protocol follow-up item rather than a parity blocker
- Audited the live export-catalog hardware-model mapping and corrected obvious non-detector mismatches that were being turned into misleading state entities:
  - `JA-114HN` now maps to `io_module` with no state entity instead of `door_opening_detector`
  - `JA-122E` now maps to `rfid_reader` with no state entity instead of a generic `custom` binary-sensor path
  - `120Z` now maps to `bus_booster` with no state entity instead of `custom`
  - the Home Assistant API runtime now removes stale `device_sensor_*` entities if a corrected mapping no longer exposes a state entity for that device, so upgraded installs do not keep old wrong door/custom sensors around
  - live verification after rebuilding the server showed the corrected catalog values for object IDs `1`, `35`, `40`, and `44`
- Improved container/server shutdown so ordinary docker restarts do not leave the server’s own privileged HID session behind:
  - the persistent HID read session now sends `UI_CONTROL_AUTHORISATION_END` (`perform_logout(...)`) before closing the underlying HID handle
  - the server CLI now sets an explicit Uvicorn graceful-shutdown timeout of `15s`
  - `docker-compose.dev.yml` now gives the container a `20s` `stop_grace_period` so FastAPI lifespan shutdown and HID logout can complete before Docker escalates to a forced kill
  - regression coverage now verifies that `PersistentSnapshotSession.close()` performs logout before the HID client is closed
- Tightened API server disconnect detection and graceful websocket shutdown for Home Assistant:
  - FastAPI lifespan shutdown now explicitly closes all `/v1/ws` clients through the websocket connection manager before panel runtime shutdown continues
  - the websocket manager gained `close_all(...)`, which issues real close frames to connected clients instead of relying on the process exit path alone
  - the Home Assistant API client websocket now uses `heartbeat=10` seconds and `receive_timeout=25` seconds so dead blackholed connections are detected in bounded time rather than waiting for TCP to give up
  - the Home Assistant websocket loop now treats a clean websocket end as a disconnect immediately, marks `last_update_success=False`, and enters the normal reconnect path instead of leaving entity availability stale until a later connect failure
  - focused regression coverage now checks websocket-manager shutdown closing and the Home Assistant client websocket heartbeat configuration
- Tightened control-identity semantics for section and PG actions:
  - explicit `code=...` action overrides are now treated as impersonation and require the new token scope `codes:impersonate` unless the supplied code is exactly the same as the server's configured panel auth code
  - newly minted admin tokens include `codes:impersonate` by default via `DEFAULT_ADMIN_SCOPES`; older existing tokens do not gain it automatically
  - the runtime now resolves the effective control code before section/PG actions and, when that code matches a known exported user, preflights the user's allowed sections/PGs before sending the HID command
  - this prevents the previous false-success case where a request without a Home Assistant override code could silently do nothing at the panel yet still return HTTP `200`
  - in the API-backed Home Assistant integration, PG switches no longer do optimistic local state flips; async switch calls now wait for the API result so denied requests stop looking locally successful
- Hardened the design further for programmable outputs to decouple maintenance rights from client control identity:
  - PG control now requires an explicit panel code on every API request; there is no fallback to the server's service/maintenance code for PG actions
  - the token store now supports optional `allowed_user_ids` metadata so tokens can be bound to specific exported Jablotron user IDs
  - when `allowed_user_ids` is present, the server resolves the supplied control code against the export catalog and rejects the action unless the code matches one of those bound users
  - this allows a Home Assistant token to be limited to a dedicated `HomeAssistant` Jablotron user even while the server itself still runs with a service-level code for config/export operations
  - the Home Assistant integration now raises a clear user-facing error for PG actions when:
    - no `Default control code` is configured
    - the supplied/default code is denied by token binding
    - the supplied/default code is valid but lacks rights for the target PG
  - the local bootstrap/admin CLI now supports `--allowed-user-id` so bound tokens can be minted without editing the SQLite database by hand
- Improved the Home Assistant setup UX for the dedicated control code:
  - the API-backed config flow now asks for `Default control code` during initial integration setup instead of only exposing it later in the options flow
  - both the API token and the control code now use password-style text selectors in the Home Assistant UI so they are treated as secrets during entry setup and option edits
  - the runtime now reads the control code from config-entry data as a fallback, so existing installs remain compatible while new installs can provide the secret up front
  - diagnostics now redact both `api_token` and `control_code`
- Extended secret rotation in the Home Assistant options flow:
  - the options dialog now accepts a replacement API token as well as a replacement control code
  - neither secret is prefilled or revealed; both fields are blank password inputs
  - leaving either field blank preserves the currently effective secret instead of clearing it
  - the runtime now prefers an option-level API token override over the original config-entry token so token rotation can happen without deleting and recreating the integration entry
- Fixed the long-standing API-backed availability regression in Home Assistant:
  - root cause: websocket disconnects correctly flipped `last_update_success=False`, but the runtime did not refresh existing entities when that availability flag changed
  - result: entities could stay shown as available indefinitely even after the API server stopped cleanly or heartbeat timeouts detected a dead connection
  - the API runtime now mirrors the old direct-HID integration’s `set_available/set_unavailable` behavior:
    - connection-health transitions refresh all registered entities
    - service-mode transitions also refresh all registered entities
  - this ensures `available` is reevaluated by Home Assistant on both disconnect and reconnect instead of depending only on later state payload changes
- Closed the last known Home Assistant parity gap around legacy device classes and manual classification:
  - the server-side device inference table now restores legacy stateful types for thermostat / thermometer and adds heuristic paths for legacy garage-door, glass-break, lock, tamper, valve, button, and keypad-with-door-style devices
  - thermostat and thermometer devices once again expose both their legacy binary state entities and their temperature sensors, matching the old integration surface
  - the Home Assistant options flow now loads the exported catalog and offers per-device manual type overrides, so unusual hardware or ambiguous names can be corrected without editing YAML or server code
  - overrides are applied locally in the Home Assistant runtime on top of the server’s inferred catalog, preserving the automatic setup path while allowing precise legacy-type restoration for systems we cannot physically test
  - `other` / `empty` overrides now suppress stale entities entirely, mirroring the old integration’s ignored-device behavior
- Improved operational logging on the API server without exposing secrets:
  - server startup and shutdown now log runtime mode, bind host/port, mTLS requirement, poll intervals, and resolved panel model/hardware/firmware once available
  - HTTP bearer-token authentication now logs missing-token and invalid-token/certificate-binding failures with request method/path and a shortened client-certificate fingerprint, while successful auth is logged at debug level with token label/id and granted scopes
  - mutating API routes now log high-signal request/deny/complete entries for:
    - section arm/disarm
    - PG on/off
    - user add/edit/delete
    - token create/revoke
  - those logs intentionally record only booleans for `code_supplied` and token/user metadata; they do not log bearer tokens or panel codes
  - websocket lifecycle is now visible in logs:
    - connect/disconnect
    - subscription acceptance / denied topics
    - manager-side close-all during shutdown
    - debug-level broadcast delivery counts and dead-connection cleanup
  - panel runtime now logs:
    - runtime start/stop
    - system-info refresh
    - catalog refresh counts
    - export retry when the first read comes back empty
    - control-action intent/completion with section/PG id, mode, and resolved exported user id when known
    - permission denials caused by Jablotron user rights or token-bound `allowed_user_ids`
    - persistent status-session creation/close and shutdown cleanup failures
- Refactored the API-backed Home Assistant runtime to stop doing expensive dynamic-entity removal on every websocket `status` frame:
  - device optional-entity cleanup is now catalog/reload-time reconciliation work instead of steady-state status work
  - steady-state `status` processing is now add-only for optional per-device entities such as signal strength, battery, temperature, pulse, and siren-voltage entities
  - stale optional entities are still removed when the catalog/device type proves they are structurally unsupported, or when the device disappears/gets ignored
  - focused regression coverage now expects optional entities to persist across later status frames that omit those values, while still allowing catalog-time cleanup on device-type changes
  - temporary websocket profiling remains in place until live Home Assistant validation confirms that the `jablotron100_api_hass_ws` asyncio warning regression is resolved; only after that should the earlier micro-optimizations be reconsidered or rolled back one by one
- After live Home Assistant validation on 2026-04-01 showed the websocket warning regression resolved in steady state:
  - first rollback candidate completed: removed the `status`/`catalog` identical-payload short-circuit because it was not materially contributing on the live system (`skipped_status=0`)
  - compile and targeted regression tests remained green after that rollback
  - second rollback candidate completed: reverted deferred/coalesced dirty-entity flush scheduling back to immediate in-path flushes
  - compile and targeted regression tests remained green after that rollback as well
  - final cleanup completed: removed the temporary websocket profiling scaffolding after the live checks stayed clean
  - the final rollback candidate (`_registry_remove_attempted_ids`) was intentionally kept, because it is directly tied to the original dynamic-entity removal hotspot and there was no evidence it was harming responsiveness
