# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: all
all: checks unit-test

.PHONY: unit-test
unit-test:
	@go test -count=1 -race -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@scripts/check_lint.sh
