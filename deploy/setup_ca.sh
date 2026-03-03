#!/usr/bin/env bash
# setup_ca.sh — Generate HoangSec Certificate Authority
# Run ONCE on the Central Server to establish the CA.
# Keep ca.key OFFLINE / in cold storage after setup.

set -euo pipefail

CA_DIR="${1:-/etc/hoangsec/ca}"
mkdir -p "$CA_DIR"

echo "[*] Generating CA private key..."
openssl genrsa -out "$CA_DIR/ca.key" 4096

echo "[*] Generating CA self-signed certificate (10 years)..."
openssl req -new -x509 -days 3650 -key "$CA_DIR/ca.key" \
  -out "$CA_DIR/ca.crt" \
  -subj "/C=VN/O=HoangSec/CN=HoangSec-CA"

chmod 600 "$CA_DIR/ca.key"
chmod 644 "$CA_DIR/ca.crt"

echo ""
echo "✅ CA ready at $CA_DIR"
echo "   ca.crt  — distribute to all agent nodes"
echo "   ca.key  — KEEP OFFLINE. Never place on agent servers."
