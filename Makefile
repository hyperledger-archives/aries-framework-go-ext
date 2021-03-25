# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0
.PHONY: all
all: checks unit-test

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: vdr-trustbloc-bdd-test
vdr-trustbloc-bdd-test: generate-test-keys
	  @cd ./test/bdd/vdr/trustbloc/;go test -count=1 -v -cover . -p 1 -timeout=40m

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@EXCLUDE_LINT_PATH=./component/vdr/indy scripts/check_lint.sh
	@LINT_PATH=./component/vdr/indy GOLANGCI_LINT_IMAGE="canislabs/golangci-lint:latest" scripts/check_lint.sh

.PHONY: generate-test-keys
generate-test-keys:
	@rm -Rf ./test/bdd/vdr/trustbloc/fixtures/keys/tls
	@mkdir -p -p test/bdd/vdr/trustbloc/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/ext \
		--entrypoint "/opt/workspace/ext/test/bdd/vdr/trustbloc/generate_test_keys.sh" \
		frapsoft/openssl
