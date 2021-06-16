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

NEW_UUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)


$cli follower --outbox-url=https://localhost:8009/services/orb/outbox --actor=$domain2IRI --to=$domain1IRI --action=Follow --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
$cli witness --outbox-url=https://testnet.orb.local/services/orb/outbox --actor=$domain1IRI --to=$domain2IRI --action=InviteWitness --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
$cli ipfs key-gen --ipfs-url=http://localhost:5001 --key-name=$NEW_UUID --privatekey-ed25519=ky9CBOWYatjVYiXtWTdBvaRvER2xdrR9u+ttF9UQa8h855Z1n6vyGmmjwiGB3bgdJ9lJeB171WJPf9KiI5lyDA
$cli ipfs webfinger-gen --ipfs-url=http://localhost:5001 --resource-url=https://testnet.orb.local --key-name=$NEW_UUID --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem
$cli ipfs webfinger-upload --ipfs-url=http://localhost:5001 --key-name=$NEW_UUID --webfinger-input-dir=./website
