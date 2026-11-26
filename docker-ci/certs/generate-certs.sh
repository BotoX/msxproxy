#!/bin/sh
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/ca.crt" ] \
    && [ -f "$CERT_DIR/webmail-ec-384.pem" ] \
    && [ -f "$CERT_DIR/webmail-rsa-3072.pem" ] \
    && [ -f "$CERT_DIR/keycloak.pem" ] \
    && [ -f "$CERT_DIR/exchange.pem" ] \
    && [ -f "$CERT_DIR/mailproxy.pem" ]; then
    echo "[certs] Existing certificates found in $CERT_DIR; reusing."
    exit 0
fi

echo "[certs] Generating Test Root CA and SAN server certificates in $CERT_DIR..."

# 1. Test Root CA
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/CN=msxproxy-test-root-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

gen_rsa_cert() {
    name="$1"
    cn="$2"
    san="$3"
    bits="${4:-2048}"

    openssl req -newkey "rsa:${bits}" -nodes \
        -keyout "$CERT_DIR/${name}.key" \
        -out "$CERT_DIR/${name}.csr" \
        -subj "/CN=${cn}"

    cat > "$CERT_DIR/${name}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${san}
EOF

    openssl x509 -req -days 365 \
        -in "$CERT_DIR/${name}.csr" \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERT_DIR/${name}.pem" \
        -extfile "$CERT_DIR/${name}.ext"

    rm -f "$CERT_DIR/${name}.csr" "$CERT_DIR/${name}.ext"
}

gen_ec_cert() {
    name="$1"
    cn="$2"
    san="$3"

    openssl ecparam -name secp384r1 -genkey -noout -out "$CERT_DIR/${name}.key"
    openssl req -new \
        -key "$CERT_DIR/${name}.key" \
        -out "$CERT_DIR/${name}.csr" \
        -subj "/CN=${cn}"

    cat > "$CERT_DIR/${name}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=${san}
EOF

    openssl x509 -req -days 365 \
        -in "$CERT_DIR/${name}.csr" \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERT_DIR/${name}.pem" \
        -extfile "$CERT_DIR/${name}.ext"

    rm -f "$CERT_DIR/${name}.csr" "$CERT_DIR/${name}.ext"
}

WEBMAIL_SANS="DNS:webmail.localhost,DNS:autodiscover.localhost,DNS:localhost,IP:127.0.0.1,IP:::1"
gen_ec_cert  webmail-ec-384   webmail.localhost   "$WEBMAIL_SANS"
gen_rsa_cert webmail-rsa-3072 webmail.localhost   "$WEBMAIL_SANS" 2048

gen_rsa_cert keycloak  keycloak.localhost  "DNS:keycloak.localhost,DNS:localhost,IP:127.0.0.1,IP:::1"
gen_rsa_cert mailproxy mailproxy.localhost "DNS:mailproxy.localhost,DNS:localhost,IP:127.0.0.1,IP:::1"
gen_rsa_cert exchange  email.uni-graz.at   "DNS:exchange.test.local,DNS:email.uni-graz.at,DNS:ex19ms01.uni-graz.at,DNS:ex19ms02.uni-graz.at,DNS:ex19ms03.uni-graz.at,DNS:ex19ms04.uni-graz.at,DNS:localhost,IP:127.0.0.1"

# Readable by non-root containers (e.g. keycloak UID 1000)
chmod 644 "$CERT_DIR"/*.crt "$CERT_DIR"/*.pem "$CERT_DIR"/*.key
echo "[certs] Done."
