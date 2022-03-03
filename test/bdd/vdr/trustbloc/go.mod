// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/trustbloc

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.8-0.20211201185059-733a3370f501
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20211217171603-637696af6620
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210820175050-dcc7a225178d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210820175050-dcc7a225178d
	github.com/trustbloc/edge-core v0.1.7-0.20210816120552-ed93662ac716
	gotest.tools/v3 v3.0.3 // indirect
)

replace github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc => ../../../../component/vdr/trustbloc/
