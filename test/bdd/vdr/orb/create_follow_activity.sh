#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

rm -rf .build
mkdir -p .build
wget https://nightly.link/trustbloc/orb/actions/artifacts/66795285.zip -O .build/orb-cli.zip
cd .build
unzip orb-cli.zip
tar -zxf orb-cli-linux-amd64.tar.gz
tar -zxf orb-cli-darwin-amd64.tar.gz

domain1IRI=https://testnet.orb.local/services/orb
domain2IRI=https://orb2/services/orb


cli=./orb-cli-linux-amd64

if [ "$OSTYPE" == "darwin20" ]; then
cli=./orb-cli-darwin-amd64
fi

$cli follower --outbox-url=https://localhost:8009/services/orb/outbox --actor=$domain2IRI --to=$domain1IRI --action=Follow --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
$cli witness --outbox-url=https://testnet.orb.local/services/orb/outbox --actor=$domain1IRI --to=$domain2IRI --action=InviteWitness --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
$cli ipfs key-gen --ipfs-url=http://localhost:5001 --key-name=key1 --privatekey-ed25519=6dFbUloT+39dRpeCAu8gVYNJu3CXD/6SJsBGSSpe0k4ON1FS5idB/HHMkjYAsrBXm+34xT1NTGFTPX3mZFsiLA || true
$cli ipfs webfinger-gen --ipfs-url=http://localhost:5001 --resource-url=https://testnet.orb.local --key-name=key1 --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem
$cli ipfs webfinger-upload --ipfs-url=http://localhost:5001 --key-name=key1 --webfinger-input-dir=./website
