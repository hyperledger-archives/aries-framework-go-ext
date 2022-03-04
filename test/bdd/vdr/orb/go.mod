// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.8-0.20220303090836-f8d34037f4c1
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20220303174620-e3a8602acbee
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210910143505-343c246c837c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20211206182816-9cdcbcd09dc2
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/sidetree-core-go v0.7.1-0.20220302221451-205719c617be
)

replace github.com/hyperledger/aries-framework-go-ext/component/vdr/orb => ../../../../component/vdr/orb/
