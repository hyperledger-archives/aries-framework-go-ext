#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

domain1IRI=https://testnet.orb.local/services/orb
domain2IRI=https://orb2/services/orb
followID=1
inviteWitnessID=2

curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" \
   --request POST \
   --data '{"@context":"https://www.w3.org/ns/activitystreams","id":"'$domain2IRI'/activities/'$followID'","type":"Follow","actor":"'$domain2IRI'","to":"'$domain1IRI'","object":"'$domain1IRI'"}' \
   --insecure https://testnet.orb.local/services/orb/inbox


curl -o /dev/null -s -w "%{http_code}" --header "Content-Type: application/json" \
   --request POST \
   --data '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"'$domain1IRI'/activities/'$inviteWitnessID'","type":"InviteWitness","actor":"'$domain1IRI'","to":"'$domain2IRI'","object":"'$domain2IRI'"}' \
   --insecure https://localhost:8009/services/orb/inbox
