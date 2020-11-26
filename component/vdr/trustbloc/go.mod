// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
module github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc

go 1.15

require (
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201110161050-249e1c428734
	github.com/phoreproject/bls v0.0.0-20200525203911-a88a5ae26844 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/trustbloc-did-method v0.1.5-0.20201113081448-0e789546b4d7
)

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
	github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)
