#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

rm -rf .build
mkdir -p .build
wget https://nightly.link/trustbloc/orb/actions/artifacts/61088009.zip -O .build/orb-cli.zip
cd .build
unzip orb-cli.zip
tar -zxf orb-cli-linux-amd64.tar.gz
tar -zxf orb-cli-darwin-amd64.tar.gz

domain1IRI=https://testnet.orb.local/services/orb
domain2IRI=https://orb2/services/orb


if [ "$OSTYPE" == "darwin"* ]; then
./orb-cli-darwin-amd64 follower --outbox-url=https://localhost:8009/services/orb/outbox --actor=$domain2IRI --to=$domain1IRI --action=Follow --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
./orb-cli-darwin-amd64 witness --outbox-url=https://testnet.orb.local/services/orb/outbox --actor=$domain1IRI --to=$domain2IRI --action=InviteWitness --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
else
./orb-cli-linux-amd64 follower --outbox-url=https://localhost:8009/services/orb/outbox --actor=$domain2IRI --to=$domain1IRI --action=Follow --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
./orb-cli-linux-amd64 witness --outbox-url=https://testnet.orb.local/services/orb/outbox --actor=$domain1IRI --to=$domain2IRI --action=InviteWitness --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
fi
