# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0
.PHONY: all
all: checks unit-test

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: vdr-trustbloc-bdd-test
vdr-trustbloc-bdd-test: generate-vdr-trustbloc-test-keys
	  @cd ./test/bdd/vdr/trustbloc/;go test -count=1 -v -cover . -p 1 -timeout=20m

.PHONY: vdr-orb-bdd-test
vdr-orb-bdd-test: generate-vdr-orb-test-keys
	  @cd ./test/bdd/vdr/orb/;go test -count=1 -run orb_ipfs -v -cover . -p 1 -timeout=20m
	  @cd ./test/bdd/vdr/orb/;UPDATE_DOCUMENT_STORE_ENABLED=true BATCH_TIMEOUT=10000 CAS_TYPE=local go test -count=1 -run orb_cas -v -cover . -p 1 -timeout=20m

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@EXCLUDE_LINT_PATH=./component/vdr/indy scripts/check_lint.sh
	@LINT_PATH=./component/vdr/indy GOLANGCI_LINT_IMAGE="canislabs/golangci-lint:latest" scripts/check_lint.sh

.PHONY: generate-vdr-trustbloc-test-keys
generate-vdr-trustbloc-test-keys:
	@rm -Rf ./test/bdd/vdr/trustbloc/fixtures/keys/tls
	@mkdir -p -p test/bdd/vdr/trustbloc/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/ext \
		--entrypoint "/opt/workspace/ext/test/bdd/vdr/trustbloc/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: generate-vdr-orb-test-keys
generate-vdr-orb-test-keys:
	@rm -Rf ./test/bdd/vdr/orb/fixtures/keys/tls
	@mkdir -p -p test/bdd/vdr/orb/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/ext \
		--entrypoint "/opt/workspace/ext/test/bdd/vdr/orb/generate_test_keys.sh" \
		frapsoft/openssl
