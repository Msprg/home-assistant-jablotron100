#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-.dev-certs}"
shift || true

SERVER_CN="jablotron-api-server-dev"
CLIENT_CN="home-assistant-dev"
DNS_NAMES=()
IP_NAMES=()

usage() {
  cat <<'EOF'
Usage:
  scripts/generate-dev-certs.sh [OUT_DIR] [--dns NAME] [--ip ADDRESS] [--server-cn NAME] [--client-cn NAME]

Examples:
  scripts/generate-dev-certs.sh
  scripts/generate-dev-certs.sh .dev-certs --ip 192.168.1.50 --dns jablotron-api-server.YOUR_DOMAIN

Notes:
  - A local development CA is generated.
  - The server certificate automatically includes:
      - localhost
      - the current hostname
      - 127.0.0.1
      - all detected non-loopback IPv4 addresses on this machine
  - Add extra --ip / --dns entries for the address Home Assistant will actually use.
EOF
}

while (($#)); do
  case "$1" in
    --dns)
      DNS_NAMES+=("$2")
      shift 2
      ;;
    --ip)
      IP_NAMES+=("$2")
      shift 2
      ;;
    --server-cn)
      SERVER_CN="$2"
      shift 2
      ;;
    --client-cn)
      CLIENT_CN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

mkdir -p "$OUT_DIR"

HOSTNAME_VALUE="$(hostname -f 2>/dev/null || hostname)"
DNS_NAMES+=("localhost" "$HOSTNAME_VALUE")
IP_NAMES+=("127.0.0.1")

if command -v hostname >/dev/null 2>&1; then
  while IFS= read -r ip; do
    [[ -n "$ip" ]] && IP_NAMES+=("$ip")
  done < <(hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d')
fi

mapfile -t DNS_UNIQ < <(printf '%s\n' "${DNS_NAMES[@]}" | awk '!seen[$0]++')
mapfile -t IP_UNIQ < <(printf '%s\n' "${IP_NAMES[@]}" | awk '!seen[$0]++')

CA_KEY="$OUT_DIR/ca.key"
CA_CSR="$OUT_DIR/ca.csr"
CA_CERT="$OUT_DIR/ca.crt"
SERVER_KEY="$OUT_DIR/server.key"
SERVER_CSR="$OUT_DIR/server.csr"
SERVER_CERT="$OUT_DIR/server.crt"
CLIENT_KEY="$OUT_DIR/client.key"
CLIENT_CSR="$OUT_DIR/client.csr"
CLIENT_CERT="$OUT_DIR/client.crt"
CA_EXT="$OUT_DIR/ca.ext"
SERVER_EXT="$OUT_DIR/server.ext"
CLIENT_EXT="$OUT_DIR/client.ext"
CA_SERIAL="$OUT_DIR/ca.srl"
SUMMARY="$OUT_DIR/README.txt"

cat >"$CA_EXT" <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

cat >"$SERVER_EXT" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=@alt_names

[alt_names]
EOF

dns_index=1
for name in "${DNS_UNIQ[@]}"; do
  printf 'DNS.%d=%s\n' "$dns_index" "$name" >>"$SERVER_EXT"
  dns_index=$((dns_index + 1))
done

ip_index=1
for address in "${IP_UNIQ[@]}"; do
  printf 'IP.%d=%s\n' "$ip_index" "$address" >>"$SERVER_EXT"
  ip_index=$((ip_index + 1))
done

cat >"$CLIENT_EXT" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl genrsa -out "$CA_KEY" 4096
openssl req -new -key "$CA_KEY" -out "$CA_CSR" -subj "/CN=Jablotron API Dev CA"
openssl x509 -req -in "$CA_CSR" -signkey "$CA_KEY" -sha256 -days 3650 \
  -out "$CA_CERT" -extfile "$CA_EXT"

openssl genrsa -out "$SERVER_KEY" 4096
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=$SERVER_CN"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -days 825 -sha256 -extfile "$SERVER_EXT"

openssl genrsa -out "$CLIENT_KEY" 4096
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=$CLIENT_CN"
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAserial "$CA_SERIAL" \
  -out "$CLIENT_CERT" -days 825 -sha256 -extfile "$CLIENT_EXT"

openssl verify -CAfile "$CA_CERT" "$SERVER_CERT" "$CLIENT_CERT" >/dev/null

cat >"$SUMMARY" <<EOF
Development mTLS material
=========================

CA certificate:
  $CA_CERT

Server certificate/key:
  $SERVER_CERT
  $SERVER_KEY

Client certificate/key:
  $CLIENT_CERT
  $CLIENT_KEY

Server SAN DNS entries:
$(printf '  - %s\n' "${DNS_UNIQ[@]}")

Server SAN IP entries:
$(printf '  - %s\n' "${IP_UNIQ[@]}")

Use this CA certificate as the trust root in clients such as:
  - jablotron_api_client_tool.py --verify $CA_CERT
  - Home Assistant tls_ca_cert

Use this client certificate pair in clients such as:
  - jablotron_api_client_tool.py --client-cert $CLIENT_CERT --client-key $CLIENT_KEY
  - Home Assistant tls_client_cert / tls_client_key
EOF

rm -f "$CA_CSR" "$SERVER_CSR" "$CLIENT_CSR" "$CA_EXT" "$SERVER_EXT" "$CLIENT_EXT"

echo "Generated development certificates in $OUT_DIR"
cat "$SUMMARY"
