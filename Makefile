# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0
.PHONY: all
all: checks unit-test

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@EXCLUDE_LINT_PATH=./component/vdr/indy scripts/check_lint.sh
	@LINT_PATH=./component/vdr/indy GOLANGCI_LINT_IMAGE="canislabs/golangci-lint:latest" scripts/check_lint.sh
