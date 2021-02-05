// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
module github.com/hyperledger/aries-framework-go-ext/component/newstorage/couchdb

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/go-kivik/couchdb/v3 v3.2.6
	github.com/go-kivik/kivik/v3 v3.2.3
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210111225112-7200091513d3
	github.com/hyperledger/aries-framework-go-ext/test/component/newstorage v0.0.0
	github.com/ory/dockertest/v3 v3.6.3
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect
)

replace github.com/hyperledger/aries-framework-go-ext/test/component/newstorage => ../../../test/component/newstorage
