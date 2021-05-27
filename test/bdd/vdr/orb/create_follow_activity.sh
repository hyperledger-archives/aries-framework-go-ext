#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

rm -rf .build
mkdir -p .build
wget https://github.com/trustbloc/orb/releases/download/v0.1.1/orb-cli-linux-amd64.tar.gz -O .build/orb-cli-linux-amd64.tar.gz
wget https://github.com/trustbloc/orb/releases/download/v0.1.1/orb-cli-darwin-amd64.tar.gz -O .build/orb-cli-darwin-amd64.tar.gz
cd .build
tar -zxf orb-cli-linux-amd64.tar.gz
tar -zxf orb-cli-darwin-amd64.tar.gz

domain1IRI=https://testnet.orb.local/services/orb
domain2IRI=https://orb2/services/orb


echo "$OSTYPE"

if [ "$OSTYPE" == "darwin20" ]; then
./orb-cli-darwin-amd64 follower --outbox-url=https://localhost:8009/services/orb/outbox --actor=$domain2IRI --to=$domain1IRI --action=Follow --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
./orb-cli-darwin-amd64 witness --outbox-url=https://testnet.orb.local/services/orb/outbox --actor=$domain1IRI --to=$domain2IRI --action=InviteWitness --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
else
./orb-cli-linux-amd64 follower --outbox-url=https://localhost:8009/services/orb/outbox --actor=$domain2IRI --to=$domain1IRI --action=Follow --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
./orb-cli-linux-amd64 witness --outbox-url=https://testnet.orb.local/services/orb/outbox --actor=$domain1IRI --to=$domain2IRI --action=InviteWitness --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
fi
