// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210811135743-532e65035d3b
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210413155718-eeb5b3c708be
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210807121559-b41545a4f1e8
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210807121559-b41545a4f1e8
	github.com/trustbloc/edge-core v0.1.7-0.20210812092729-6c61997fa9dd
	gotest.tools/v3 v3.0.3 // indirect
)

replace (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb => ../../../../component/vdr/orb/
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree => ../../../../component/vdr/sidetree/
)
