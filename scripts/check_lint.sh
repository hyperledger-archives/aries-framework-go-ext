#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

echo "Run specific linter by setting LINT_PATH and GOLANGCI_LINT_IMAGE environment variables before running make lint"
echo "Sample #1: export LINT_PATH=./component/vdr/orb"
echo "Sample #1: export GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.39.0""
echo "Sample #2: export LINT_PATH=./component/vdr/longform"
echo "Sample #2: export GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.50.0""
echo "Sample #3: export LINT_PATH=./component/vdr/sidetree"
echo "Sample #2: export GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.50.0""
echo "Sample #3: export LINT_PATH=./component/vdr/indy"
echo "Sample #3: export GOLANGCI_LINT_IMAGE="canislabs/golangci-lint:latest""
echo "For all other components use Sample #1 GOLANGCI_LINT_IMAGE"
echo "Your current settings: LINT_PATH=$LINT_PATH and GOLANGCI_LINT_IMAGE=$GOLANGCI_LINT_IMAGE"

lint_path=$1
if [ -z "$lint_path" ]; then
  lint_path="${LINT_PATH}"
fi

DOCKER_CMD=${DOCKER_CMD:-docker}

if [ -z "${EXCLUDE_LINT_PATH}" ]; then
  exclude=""
else
  exclude="-path ${EXCLUDE_LINT_PATH} -prune -o"
fi


if [ -z "${GOLANGCI_LINT_IMAGE}" ]; then
  lint_image="golangci/golangci-lint:v1.39.0"
else
  lint_image="${GOLANGCI_LINT_IMAGE}"
fi

if [ -z "$lint_path" ]; then
  lint_path=./
fi

ROOT=$(pwd)

function clean ()
{
  if [ "$ROOT" != "$(pwd)" ]; then
    rm -f "$(pwd)/.golangci.yml"
  fi
}

trap exit INT
trap clean EXIT

for i in $(find $lint_path $exclude -name "go.mod")
do
  pushd "$(dirname $i)" > /dev/null
  if [ -z $(go list 2> /dev/null) ]; then
      echo "skipped $(dirname $i)"
      popd  > /dev/null
      continue
  fi

  if [ -f "$ROOT/$(dirname $i)/.custom_golangci.yml" ]; then
      # use local lint config
      ${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} \
      -v "$ROOT:/opt/workspace" \
      -v "$ROOT/$lint_path/.custom_golangci.yml:/opt/workspace/$(dirname $i)/.custom_golangci.yml" \
      -w "/opt/workspace/$(dirname $i)" \
      ${lint_image} golangci-lint run -c "/opt/workspace/$(dirname $i)/.custom_golangci.yml" \
      --path-prefix "$(dirname $i)/"
  else # use main lint config
      ${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} \
      -v "$ROOT:/opt/workspace" \
      -v "$ROOT/.golangci.yml:/opt/workspace/$(dirname $i)/.golangci.yml" \
      -w "/opt/workspace/$(dirname $i)" \
      ${lint_image} golangci-lint run --path-prefix "$(dirname $i)/"
  fi

  clean

  echo "linted $(dirname $i)"
  popd  > /dev/null
done
