# Development mTLS Setup

This server requires mutual TLS. For development and alpha testing, the simplest workable approach is:

- generate your own local CA
- use that CA to sign one server certificate
- use that CA to sign one Home Assistant client certificate

This is still real mTLS, just with a private development trust root instead of a public CA.

## Why not "accept anything"?

TLS cannot safely "accept anything" and still give you the transport guarantees you want. If you connect by IP address, that IP must be present in the server certificate SAN. If you connect by hostname, that hostname must be present in the SAN.

For development, the practical solution is to generate a server certificate that includes:

- `127.0.0.1`
- `localhost`
- the host machine's current non-loopback IPv4 addresses
- any extra IPs or DNS names you pass explicitly

## Generate the files

From the repo root:

```bash
chmod +x scripts/generate-dev-certs.sh
scripts/generate-dev-certs.sh .dev-certs \
  --ip 192.168.1.50 \
  --dns jablotron-api-server.brainit.tech
```

If you do not pass `--ip` or `--dns`, the script still includes `127.0.0.1`, `localhost`, the current hostname, and the machine's currently detected LAN IPv4 addresses.

Generated files:

- `.dev-certs/ca.crt`
- `.dev-certs/ca.key`
- `.dev-certs/server.crt`
- `.dev-certs/server.key`
- `.dev-certs/client.crt`
- `.dev-certs/client.key`

## Fastest dev server path

Generate the certs:

```bash
scripts/generate-dev-certs.sh .dev-certs --ip 127.0.0.1
mkdir -p .dev-data
```

Run the server in demo mode first:

```bash
JABLOTRON_API_RUNTIME_MODE=demo docker compose -f docker-compose.dev.yml up --build
```

Create an admin token:

```bash
python3 jablotron_api_admin_tool.py --db-path ./.dev-data/jablotron-api.db --label dev-admin
```

Test from this repo:

```bash
python3 jablotron_api_client_tool.py system \
  --base-url https://127.0.0.1:8443 \
  --token YOUR_TOKEN \
  --verify ./.dev-certs/ca.crt \
  --client-cert ./.dev-certs/client.crt \
  --client-key ./.dev-certs/client.key
```

## Live panel server path

Once the demo path works, switch to live mode:

```bash
JABLOTRON_API_RUNTIME_MODE=live docker compose -f docker-compose.dev.yml up --build
```

If device auto-discovery is not enough, add the panel environment overrides when launching:

```bash
JABLOTRON_PANEL_PORT=/dev/hidraw0 \
JABLOTRON_PANEL_FLEXI_CFG_DEVICE=/dev/sdb1 \
JABLOTRON_PANEL_FLEXI_LOG_DEVICE=/dev/sdd1 \
docker compose -f docker-compose.dev.yml up --build
```

## Home Assistant values

In the `jablotron100-api-HASS` config flow, use:

- `server_url`: `https://192.168.1.50:8443` or `https://jablotron-api-server.brainit.tech:8443`
- `api_token`: the token you bootstrapped
- `tls_ca_cert`: path to `ca.crt` on the Home Assistant machine
- `tls_client_cert`: path to `client.crt` on the Home Assistant machine
- `tls_client_key`: path to `client.key` on the Home Assistant machine

The important rule is simple: if Home Assistant uses an IP in `server_url`, that IP must have been included with `--ip` when the certs were generated. If Home Assistant uses a hostname, that hostname must have been included with `--dns`.
