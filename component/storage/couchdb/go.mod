// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
module github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/flimzy/diff v0.1.7 // indirect
	github.com/flimzy/testy v0.1.17 // indirect
	github.com/go-kivik/couchdb v2.0.0+incompatible
	github.com/go-kivik/kivik v2.0.0+incompatible
	github.com/go-kivik/kiviktest v2.0.0+incompatible // indirect
	github.com/google/uuid v1.1.2
	github.com/gopherjs/gopherjs v0.0.0-20200217142428-fce0ec30dd00 // indirect
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201028195746-556cee009e20
	github.com/hyperledger/aries-framework-go-ext/test/component/storage v0.0.0
	github.com/ory/dockertest/v3 v3.6.2
	github.com/stretchr/testify v1.6.1
	gitlab.com/flimzy/testy v0.3.2 // indirect
)

replace github.com/hyperledger/aries-framework-go-ext/test/component/storage => ../../../test/component/storage
