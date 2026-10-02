[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg?style=for-the-badge)](https://github.com/hacs/default)

# Jablotron 100+

Home Assistant custom component for JABLOTRON 100+ alarm system.

Tested with JA-100K, JA-101K, JA-101K-LAN, JA-103K, JA-103KRY, JA-106K-3G, JA-107K and JA-14K.

## API Server Alpha

This repository now also contains a Python `jablotron-api-server` that owns the USB/FLEXI panel connection and exposes a scoped `HTTPS` + `WebSocket` API for clients such as the Home Assistant integration.

### v1 stability promise

The `/v1` REST and WebSocket surface is being locked for the public alpha. Within the v1 series:

- REST paths under `/v1/...` will not be renamed or removed, only deprecated (with a `Deprecation` flag in the OpenAPI document) before any eventual removal in a future major version.
- Response shapes (the Pydantic models in `src/jablotron_api/domain/models.py`) will only be extended in backward-compatible ways: new optional fields, never removed or retyped existing ones.
- The token scope vocabulary (the `Scope` enum) is fixed. Scope names will not be renamed; new scopes can be added. The legacy `status:read` and `sections:control` names are auto-migrated to the v1 names on TokenStore startup for the duration of the v1 alpha window.
- WebSocket topic names (`status`, `events`, `users`, `catalog`, `system`) and the envelope shape (`{sequence, topic, event, timestamp, payload}`) are fixed.
- Error responses use a consistent shape: HTTP status code plus a JSON body with `detail` containing either a string, `{error, missing|missing_any_of}` for scope denials, or `{error: "user_write_rejected", reason, message, violations, conflicting_user_ids}` when a user record breaks a panel rule (see [docs/user-code-rules.md](docs/user-code-rules.md)).

The authoritative description is `docs/openapi.v1.json`, generated from the running FastAPI app. To regenerate it after changes:

```bash
venv/bin/python -m jablotron_api.cli.main openapi-export docs/openapi.v1.json
```

### Catalog freshness

Reads of the exported catalog and the user table are **demand-driven**: the
server caches the last panel read and refreshes it only when a request
arrives whose freshness requirement the cache cannot meet. Nothing refreshes
the catalog on a timer, so an idle server does no panel work — which matters
because every catalog read enters the panel's configuration mode and takes
~16 s (see [docs/panel-export-freshness.md](docs/panel-export-freshness.md)).

- `GET /v1/export/catalog`, `GET /v1/users`, `GET /v1/users/{id}` and
  `GET /v1/export/users` accept `?max_age_seconds=`. The cache is served when
  it is at most that old; otherwise the panel is read.
- Omitting the parameter uses the server's configured default,
  `JABLOTRON_PANEL_CATALOG_MAX_AGE_SECONDS` (default `3600`). The default is
  finite by design.
- `max_age_seconds=0` means a read that *started at or after the request
  arrived* — a request that joins a pull which began earlier chains its own.
  Use it before acting on the panel's contents.
- Concurrent requests that need a read join one in-flight read rather than
  queueing several against the panel.
- Every catalog response carries `as_of` (when the underlying export was
  read), `source` (`panel` or `cache`) and `trigger_used`, so a client can
  verify freshness instead of trusting it.
- `GET /v1/export/time-limits` and `GET /v1/export/communications` keep their
  always-fresh semantics and take no `max_age_seconds`.

The `/v1/events/recent` path is a deprecated alias for `/v1/events?limit=...&kinds=...` and will be removed after the v1 alpha window.

### Quick start

1. Build the image:

```bash
docker build -t jablotron-api-server:latest .
```

2. Create a CA, server certificate, and client certificate. The server expects mTLS, so the client must present a certificate signed by the configured CA. For development and alpha testing, the repo now includes a helper that generates a local development CA and matching server/client certs:

```bash
chmod +x scripts/generate-dev-certs.sh
scripts/generate-dev-certs.sh .dev-certs \
  --ip 127.0.0.1 \
  --dns jablotron-api-server.YOUR_DOMAIN
mkdir -p .dev-data
```

If you will connect from Home Assistant by LAN IP, add that IP with another `--ip` flag. See [docs/dev-mtls.md](docs/dev-mtls.md).

3. Run the server in demo mode for a full smoke test without panel hardware:

```bash
docker run --rm -p 8443:8443 \
  -e JABLOTRON_API_RUNTIME_MODE=demo \
  -e JABLOTRON_API_TLS_CERTFILE=/data/certs/server.crt \
  -e JABLOTRON_API_TLS_KEYFILE=/data/certs/server.key \
  -e JABLOTRON_API_TLS_CA_CERTS=/data/certs/ca.crt \
  -v "$PWD/data:/data" \
  jablotron-api-server:latest
```

4. Bootstrap an admin token in the mounted data directory:

```bash
python3 jablotron_api_admin_tool.py --db-path ./data/jablotron-api.db --label alpha-admin
```

5. Verify the API with the reference client:

```bash
python3 jablotron_api_client_tool.py system \
  --base-url https://127.0.0.1:8443 \
  --token YOUR_TOKEN \
  --verify ./data/certs/ca.crt \
  --client-cert ./data/certs/client.crt \
  --client-key ./data/certs/client.key

python3 jablotron_api_client_tool.py status \
  --base-url https://127.0.0.1:8443 \
  --token YOUR_TOKEN \
  --verify ./data/certs/ca.crt \
  --client-cert ./data/certs/client.crt \
  --client-key ./data/certs/client.key
```

The packaged entrypoint is also available after installation:

```bash
jablotron-api-client events recent --limit 20 \
  --base-url https://127.0.0.1:8443 \
  --token YOUR_TOKEN \
  --verify ./data/certs/ca.crt \
  --client-cert ./data/certs/client.crt \
  --client-key ./data/certs/client.key
```

The reference client covers the full `/v1` API surface, including `users list|get|create|patch|delete`,
`tokens list|create|revoke`, `export-catalog`, `export-time-limits`, `export-communications`,
section/PG control, and WebSocket subscriptions.

6. Switch `JABLOTRON_API_RUNTIME_MODE=live` and provide the panel USB/block devices to start validating the real hardware path.
   User create/edit/delete follows the rights the panel grants the login code,
   the same way F-Link does. A code with *master* rights (the usual
   administrator code) writes the user record over HID; a code with *service*
   or *ARC* rights writes it through the panel's `IMPORT.CFG` volume, which
   needs the FLEXI block device and a mount. The server logs in once before
   each write to read the rights and picks the path (`JABLOTRON_PANEL_WRITE_TRANSPORT=auto`,
   the default); set it to `hid` or `storage` to skip the probe and force one.
   `JABLOTRON_PANEL_WRITE_AUTH_CODE` is optional: when set, user writes log in
   with it instead of `JABLOTRON_PANEL_AUTH_CODE`, and every other session keeps
   using `JABLOTRON_PANEL_AUTH_CODE`. A write the panel refuses answers `409`.

### Home Assistant alpha path

- The integration now connects to the API server instead of direct USB/HID access.
- Section names, PG names, and discovered peripheral metadata are pulled from `/v1/export/catalog`; they no longer need to be counted and named manually in the config flow.
- The integration config flow now asks for `server_url`, `api_token`, optional CA/client certificate paths, and an optional default control code.
- The HACS-installable API integration now lives only in the `jablotron100-api-HASS` git submodule under the non-conflicting domain `jablotron100_api_hass`, so it can be installed alongside the original `jablotron100` integration.
- The root `custom_components/jablotron100` tree in this repo is the legacy direct-HID/reference integration, not the maintained API-backed integration.

### Home Assistant install, test, and debug

The best current workflow is:

1. Run the API server from this checkout on the machine that has the panel attached.

```bash
python3 -m jablotron_api.cli.main server \
  --host 0.0.0.0 \
  --port 8443 \
  --tls-certfile /path/to/server.crt \
  --tls-keyfile /path/to/server.key \
  --tls-ca-certs /path/to/ca.crt \
  --panel-port auto \
  --panel-auth-code "$JABLOTRON_PANEL_AUTH_CODE"
```

2. Generate development certs if you have not already:

```bash
scripts/generate-dev-certs.sh .dev-certs \
  --ip YOUR_SERVER_LAN_IP \
  --dns jablotron-api-server.YOUR_DOMAIN
```

3. Create a client certificate and token for Home Assistant. Use scopes at least `system:read`, `sections:read`, `pgs:read`, `devices:read`, `catalog:read`, `events:read`, `sections:arm`, `sections:disarm`, and `pgs:control`. Add `codes:impersonate` if Home Assistant will forward a user-supplied code that differs from the server's service code.

4. Install the API-backed custom component from the submodule into the Home Assistant config directory as a symlink or copy. During active development, a symlink is the fastest option:

```bash
ln -s /home/administrator/home-assistant-jablotron100/jablotron100-api-HASS/custom_components/jablotron100_api_hass \
  /path/to/home-assistant-config/custom_components/jablotron100_api_hass
```

5. Put the CA certificate, Home Assistant client certificate, and Home Assistant client key somewhere the Home Assistant process can read them.

6. Restart Home Assistant, add the `jablotron100-api-HASS` integration, and enter:
   - `server_url`: `https://HOST:8443`
   - `api_token`
   - `tls_ca_cert`
   - `tls_client_cert`
   - `tls_client_key`
   - optional `Default control code`

7. Test the parity-critical paths first:
   - arm and disarm each section
   - toggle PG outputs
   - confirm device binary sensors update
   - confirm temperature sensors, wireless battery levels, and wireless signal strengths appear
   - confirm LAN and GSM entities appear where the panel model supports them
   - if `require_code_to_arm` or `require_code_to_disarm` is enabled, intentionally enter a bad code once and confirm the `jablotron100_wrong_code` event fires

8. Turn on debug logging in Home Assistant while testing:

```yaml
logger:
  logs:
    custom_components.jablotron100_api_hass: debug
```

9. Attach your debugger to the Home Assistant `debugpy` port you already enabled in `configuration.yaml`. The most useful breakpoints are usually in:
   - `jablotron100-api-HASS/custom_components/jablotron100_api_hass/api_runtime.py`
   - `jablotron100-api-HASS/custom_components/jablotron100_api_hass/api_client.py`
   - `jablotron100-api-HASS/custom_components/jablotron100_api_hass/alarm_control_panel.py`
   - `jablotron100-api-HASS/custom_components/jablotron100_api_hass/binary_sensor.py`
   - `jablotron100-api-HASS/custom_components/jablotron100_api_hass/sensor.py`
   - `jablotron100-api-HASS/custom_components/jablotron100_api_hass/switch.py`

10. If you also want to debug the server side, run the server under `debugpy` separately from Home Assistant:

```bash
python3 -m debugpy --listen 127.0.0.1:5679 -m jablotron_api.cli.main server \
  --host 0.0.0.0 \
  --port 8443 \
  --tls-certfile /path/to/server.crt \
  --tls-keyfile /path/to/server.key \
  --tls-ca-certs /path/to/ca.crt \
  --panel-port auto \
  --panel-auth-code "$JABLOTRON_PANEL_AUTH_CODE"
```


## Features

### Sections

- States are reported to Home Assistant.
- You can arm/disarm all sections. Supported states are `arm_away` (= armed) and `arm_night`/`arm_home` (choose in options what means "armed partially" for you).
- Event `jablotron100_wrong_code` is triggered when wrong code is inserted in Home Assistant.
- Problem in a section is reported in specific "problem" sensor.

### Devices

- Devices with two states (on/off, active/inactive, open/closed etc.) are supported.
- Sabotage or problem of the device is supported in specific "problem" sensor.
- Temperature is reported for thermostats, thermometers and smoke detectors.
- Pulses are reported for electricity meters with pulse output.
- Signal strength is reported for wireless devices.
- Battery level is reported for devices with battery.

### PG outputs

- States are reported to Home Assistant.
- It's possible to turn on/off all PG outputs.

### Central unit

- State of LAN connection is reported to Home Assistant for supported central units.
- Strength of GSM signal is reported for supported central units.


## Before installation

1. Connect the USB cable to Jablotron central unit
2. Restart the Home Assistant OS

## Installation

- If you use code with a prefix, insert the code with the asterisk, e.g. `12*3456`.
- Use code of administrator to make devices work. If you cannot use code of administrator, or you don't want to use devices, set the number of devices to 0.
- You have to set devices in the same order as you see them in your J-Link/F-Link/mobile application. Ignore the central unit on position 0.
- If you want to use PG outputs, the user of the code has to have rights to control the PG outputs. Set the number of PG outputs to 0 to ignore them.


Serial port should be automatically detected. If not, you can detect it manually and set it during integration installation.

```
$ dmesg | grep usb
$ dmesg | grep hid
```

The cable should be connected as `/dev/hidraw[x]`, `/dev/ttyUSB0` or similar.

The `HACS` and `Manual` sections below are for the legacy direct-HID `jablotron100` integration that remains in this repo for reference. They are not the API-backed install path. The API-backed install path is the `jablotron100-api-HASS` submodule described above.


### HACS

1. Install the integration via [HACS](https://hacs.xyz/) (Home Assistant Community Store)  
    <small>*HACS is a third party community store and is not included in Home Assistant out of the box.*</small>
2. Restart Home Assistant
3. Jablotron integration should be available in the integrations UI

### Manual

1. [Download integration](https://github.com/kukulich/home-assistant-jablotron100/releases/)
2. Copy the folder `custom_components/jablotron100` from the zip to your config directory for the legacy direct-HID integration
3. Restart Home Assistant
4. Jablotron integration should be available in the integrations UI


## Check

1. Try to arm/disarm all sections
2. Try to activate all devices if possible (open/close door/window, move ahead of motion sensor etc.) and check if Home Assistant see the state changes
3. Check log - it should be empty when everything works
4. Does any problem occur? Report [issue](https://github.com/kukulich/home-assistant-jablotron100/issues) or join [Discord](https://discord.gg/bNmaB6n)

Even if everything works for you, you can join the [Discord](https://discord.gg/bNmaB6n).
We would be happy:
 - If you report model of you Jablotron central unit, so we know that integration works on another model
 - If you can test some things (e.g. LAN), so we can make the integration more robust

The communication in Discord is mostly in Czech or Slovak but don't be afraid - you can use English as well.


## Debugging
1. Enable debug logging for the Jablotron intergation via the [logger](https://www.home-assistant.io/integrations/logger/) integration by adding the following lines to the `configuration.yaml` file.
```
logger:
  default: info
  logs: 
    custom_components.jablotron100: debug
```

2. Enable debug logging in the Jablotron integration. Go to the Integration page of your Home Assistant and click on the `Configure` button belonging to the Jablotron integration and then select `Debugging` to specify specific debugging options, such as `Log all incoming packets`. Finish the configuration by pressing the `Submit` button.
3. After enabling 1. and 2., the home assistant log should contain debug log of the Jablotron integration, e.g.,
```
2022-02-17 10:57:19 DEBUG (ThreadPoolExecutor-2_0) [custom_components.jablotron100] Incoming: 801a0cffffffff010001002820010027ffffffffffffffffffffffff
2022-02-17 10:57:19 DEBUG (ThreadPoolExecutor-2_0) [custom_components.jablotron100] Incoming: 5203820113
```
4. Restart Home Assistant

## Credits

Big thanks to [plaksnor](https://github.com/plaksnor/), [Horsi70](https://github.com/Horsi70/) and [Shamshala](https://github.com/Shamshala/) for their work on previous integration.
