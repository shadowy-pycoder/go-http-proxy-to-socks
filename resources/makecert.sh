#!/usr/bin/env bash

set -ex

tee rootCA.cnf >/dev/null <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
C=US
O=GoHPTSProxy
CN=GoHPTS Proxy CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

tee server.ext >/dev/null <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl genpkey -algorithm RSA -out rootCA.key -pkeyopt rsa_keygen_bits:4096

openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 -out rootCA.crt -config rootCA.cnf

openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

openssl req -new -key server.key -out server.csr -subj "/C=US/O=GoHPTSProxy/CN=localhost"

openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server.ext
