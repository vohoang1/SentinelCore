#!/usr/bin/env bash
# generate_agent_cert.sh — Issue a new agent certificate signed by the HoangSec CA
# Usage: ./generate_agent_cert.sh <server-hostname>

set -euo pipefail

HOSTNAME="${1:?Usage: $0 <server-hostname>}"
CA_DIR="${2:-/etc/hoangsec/ca}"
OUT_DIR="${3:-/etc/hoangsec}"

mkdir -p "$OUT_DIR"

echo "[*] Generating agent key for: $HOSTNAME"
openssl genrsa -out "$OUT_DIR/agent.key" 2048

echo "[*] Creating CSR..."
openssl req -new -key "$OUT_DIR/agent.key" \
  -out "$OUT_DIR/agent.csr" \
  -subj "/C=VN/O=HoangSec/CN=$HOSTNAME"

echo "[*] Signing with CA..."
openssl x509 -req -days 365 \
  -in "$OUT_DIR/agent.csr" \
  -CA "$CA_DIR/ca.crt" \
  -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial \
  -out "$OUT_DIR/agent.crt"

# Extract fingerprint for agent registration
FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 \
  -in "$OUT_DIR/agent.crt" | cut -d= -f2 | tr -d ':')

rm -f "$OUT_DIR/agent.csr"
chmod 600 "$OUT_DIR/agent.key"
chmod 644 "$OUT_DIR/agent.crt"

echo ""
echo "✅ Cert issued for $HOSTNAME"
echo "   Fingerprint: $FINGERPRINT"
echo ""
echo "Register this agent with:"
echo "   POST /api/v1/agents/register"
echo "   { \"hostname\": \"$HOSTNAME\", \"cert_fingerprint\": \"$FINGERPRINT\", ... }"
