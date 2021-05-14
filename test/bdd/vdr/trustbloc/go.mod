// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/trustbloc

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210512223230-d4aa62b079bc
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210423164427-96362080a25e
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210429205242-c5e97865879c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210429205242-c5e97865879c
	github.com/trustbloc/edge-core v0.1.7-0.20210429222332-96b987820e63
	gotest.tools/v3 v3.0.3 // indirect
)

replace github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc => ../../../../component/vdr/trustbloc/
