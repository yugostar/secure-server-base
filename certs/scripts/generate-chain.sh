#!/usr/bin/env bash
set -euo pipefail

# Lab 6: generate certificate chain (3 links)
# Root CA -> Intermediate CA -> Server cert (localhost)
#
# Требование: идентификатор студента должен быть в сертификатах.
# Передайте STUDENT_ID=... (номер студенческого билета)

STUDENT_ID="${STUDENT_ID:-}"
if [[ -z "$STUDENT_ID" ]]; then
  echo "ERROR: STUDENT_ID env is required (номер студенческого билета)" >&2
  echo "Example: STUDENT_ID=123456 ./certs/scripts/generate-chain.sh" >&2
  exit 1
fi

OUT_DIR="certs/out"
CFG="certs/config/openssl.cnf"
mkdir -p "$OUT_DIR"

# уникальные имена (не как в примере)
ROOT_NAME="rs-root-ca"
INT_NAME="rs-intermediate-ca"
SRV_NAME="rs-secure-server-server"

ROOT_KEY="$OUT_DIR/${ROOT_NAME}.key"
ROOT_CRT="$OUT_DIR/${ROOT_NAME}.crt"

INT_KEY="$OUT_DIR/${INT_NAME}.key"
INT_CSR="$OUT_DIR/${INT_NAME}.csr"
INT_CRT="$OUT_DIR/${INT_NAME}.crt"

SRV_KEY="$OUT_DIR/${SRV_NAME}.key"
SRV_CSR="$OUT_DIR/${SRV_NAME}.csr"
SRV_CRT="$OUT_DIR/${SRV_NAME}.crt"

CHAIN_PEM="$OUT_DIR/${SRV_NAME}-chain.pem"
TRUST_PEM="$OUT_DIR/${ROOT_NAME}-trust.pem"
P12="$OUT_DIR/rs-secure-server-keystore.p12"
P12_PASS="${KEYSTORE_PASSWORD:-changeit}"
P12_ALIAS="${KEYSTORE_ALIAS:-rs-secure-server}"

echo "Generating Root CA..."
openssl genrsa -out "$ROOT_KEY" 4096
openssl req -x509 -new -nodes -key "$ROOT_KEY" -sha256 -days 3650   -subj "/C=RU/O=RS Secure Server/CN=RS Root CA/serialNumber=$STUDENT_ID"   -extensions v3_root_ca -config "$CFG"   -out "$ROOT_CRT"

echo "Generating Intermediate CA..."
openssl genrsa -out "$INT_KEY" 4096
openssl req -new -key "$INT_KEY"   -subj "/C=RU/O=RS Secure Server/CN=RS Intermediate CA/serialNumber=$STUDENT_ID"   -out "$INT_CSR"
openssl x509 -req -in "$INT_CSR" -CA "$ROOT_CRT" -CAkey "$ROOT_KEY" -CAcreateserial   -out "$INT_CRT" -days 1825 -sha256 -extfile "$CFG" -extensions v3_intermediate_ca

echo "Generating Server certificate for localhost..."
openssl genrsa -out "$SRV_KEY" 2048
openssl req -new -key "$SRV_KEY"   -subj "/C=RU/O=RS Secure Server/CN=localhost/serialNumber=$STUDENT_ID"   -out "$SRV_CSR"
openssl x509 -req -in "$SRV_CSR" -CA "$INT_CRT" -CAkey "$INT_KEY" -CAcreateserial   -out "$SRV_CRT" -days 825 -sha256 -extfile "$CFG" -extensions v3_server

echo "Building chain (server + intermediate + root)..."
cat "$SRV_CRT" "$INT_CRT" "$ROOT_CRT" > "$CHAIN_PEM"
cp "$ROOT_CRT" "$TRUST_PEM"

echo "Creating PKCS12 keystore (NOT committed to git)..."
openssl pkcs12 -export -out "$P12" -inkey "$SRV_KEY" -in "$SRV_CRT"   -certfile <(cat "$INT_CRT" "$ROOT_CRT")   -name "$P12_ALIAS" -passout pass:"$P12_PASS"

echo
echo "DONE."
echo "Keystore: $P12 (password from KEYSTORE_PASSWORD or default 'changeit')"
echo "Trust root: $TRUST_PEM"
echo
echo "To run HTTPS:"
echo "  export SSL_ENABLED=true"
echo "  export SERVER_PORT=8443"
echo "  export SSL_KEYSTORE_PATH=$P12"
echo "  export SSL_KEYSTORE_PASSWORD=$P12_PASS"
