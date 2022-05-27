#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

rm -rf .build
mkdir -p .build
wget https://github.com/trustbloc/orb/releases/download/v0.1.3/orb-cli-linux-amd64.tar.gz -O .build/orb-cli-linux-amd64.tar.gz
wget https://github.com/trustbloc/orb/releases/download/v0.1.3/orb-cli-darwin-amd64.tar.gz -O .build/orb-cli-darwin-amd64.tar.gz
cd .build
tar -zxf orb-cli-linux-amd64.tar.gz
tar -zxf orb-cli-darwin-amd64.tar.gz

domain1IRI=https://testnet.orb.local/services/orb
domain2IRI=https://orb2/services/orb


cli=./orb-cli-linux-amd64

keyID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

if [ "$OSTYPE" == "darwin21" ]; then
cli=./orb-cli-darwin-amd64
keyID=$RANDOM
fi


$cli follower --outbox-url=https://localhost:8009/services/orb/outbox --actor=$domain2IRI --to=$domain1IRI --action=Follow --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
$cli witness --outbox-url=https://testnet.orb.local/services/orb/outbox --actor=$domain1IRI --to=$domain2IRI --action=InviteWitness --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem --auth-token=ADMIN_TOKEN
#$cli ipfs key-gen --ipfs-url=http://localhost:5001 --key-name=$keyID --privatekey-ed25519=9kRTh70Ut0MKPeHY3Gdv/pi8SACx6dFjaEiIHf7JDugPpXBnCHVvRbgdzYbWfCGsXdvh/Zct+AldKG4bExjHXg
#$cli ipfs host-meta-doc-gen --ipfs-url=http://localhost:5001 --resource-url=https://testnet.orb.local --key-name=$keyID --tls-cacerts=../fixtures/keys/tls/ec-cacert.pem
#$cli ipfs host-meta-dir-upload --ipfs-url=http://localhost:5001 --key-name=$keyID --host-meta-input-dir=./website
