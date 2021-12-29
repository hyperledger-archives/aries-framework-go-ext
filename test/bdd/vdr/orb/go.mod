// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.8-0.20211217135421-f68d5698237a
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20211217171603-637696af6620
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210910143505-343c246c837c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20211206182816-9cdcbcd09dc2
	github.com/trustbloc/edge-core v0.1.7
)

replace (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb => ../../../../component/vdr/orb/
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree => ../../../../component/vdr/sidetree/
)
