// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go-ext/component/storage/postgresql

go 1.17

require (
	github.com/cenkalti/backoff/v4 v4.1.2
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20220330140627-07042d78580c
	github.com/hyperledger/aries-framework-go/test/component v0.0.0-20220330140627-07042d78580c
	github.com/jackc/pgx/v4 v4.11.0
	github.com/ory/dockertest/v3 v3.8.1
	github.com/stretchr/testify v1.7.0
	github.com/valyala/fastjson v1.6.3
)

require golang.org/x/text v0.3.5 // indirect
