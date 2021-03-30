// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb

go 1.15

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210330153939-7ec3a2c4697c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210330163233-9482b4291d8e
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210320144851-40976de98ccf
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210320144851-40976de98ccf
	github.com/trustbloc/edge-core v0.1.4-0.20200709143857-e104bb29f6c6
)

replace github.com/hyperledger/aries-framework-go-ext/component/vdr/orb => ../../../../component/vdr/orb/
