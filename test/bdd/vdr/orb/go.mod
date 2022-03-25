// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb

go 1.17

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.8-0.20220324201531-18c87667df19
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20220325181924-aed46b24a321
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20220324201531-18c87667df19
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20220324201531-18c87667df19
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/sidetree-core-go v0.7.1-0.20220314104818-0ae9fc89df5b
)

replace github.com/hyperledger/aries-framework-go-ext/component/vdr/orb => ../../../../component/vdr/orb/
