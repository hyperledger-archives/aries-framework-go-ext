// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/trustbloc

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210421205521-3974f6708723
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210330163233-9482b4291d8e
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210409151411-eeeb8508bd87
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210412201938-efffe3eafcd1
	github.com/trustbloc/edge-core v0.1.4-0.20200709143857-e104bb29f6c6
)

replace github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc => ../../../../component/vdr/trustbloc/
