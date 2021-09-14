// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210913152107-80cff90741e9
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210817192417-e46e251f4caf
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210910143505-343c246c837c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210910143505-343c246c837c
	github.com/trustbloc/edge-core v0.1.7-0.20210819195944-a3500e365d5c
)

replace (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb => ../../../../component/vdr/orb/
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree => ../../../../component/vdr/sidetree/
)
