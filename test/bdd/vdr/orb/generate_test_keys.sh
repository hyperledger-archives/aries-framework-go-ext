#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo "Generating vdr-orb Test PKI"

cd /opt/workspace/ext
mkdir -p test/bdd/vdr/orb/fixtures/keys/tls
tmp=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = testnet.orb.local
DNS.3 = orb2" >> "$tmp"


#create CA
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/vdr/orb/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/bdd/vdr/orb/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/bdd/vdr/orb/fixtures/keys/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/vdr/orb/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/bdd/vdr/orb/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:vdr-orb/OU=vdr-orb/CN=localhost" -out test/bdd/vdr/orb/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/bdd/vdr/orb/fixtures/keys/tls/ec-key.csr -CA test/bdd/vdr/orb/fixtures/keys/tls/ec-cacert.pem -CAkey test/bdd/vdr/orb/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -extfile "$tmp" -out test/bdd/vdr/orb/fixtures/keys/tls/ec-pubCert.pem -days 365

mkdir -p test/bdd/vdr/orb/fixtures/keys/kms
openssl rand 32 | base64 | sed 's/+/-/g; s/\//_/g' > test/bdd/vdr/orb/fixtures/keys/kms/secret-lock.key

echo "done generating vdr-orb PKI"
