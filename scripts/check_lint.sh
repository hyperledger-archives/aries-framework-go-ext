#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

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
  lint_image="golangci/golangci-lint:v1.31.0"
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
  if [ -z $(go list) ]; then
      popd  > /dev/null
      continue
  fi

  ${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} \
  -v "$(pwd):/opt/workspace" \
  -v "$ROOT/.golangci.yml:/opt/workspace/.golangci.yml" \
  -w "/opt/workspace" \
  ${lint_image} golangci-lint run

  clean

  popd  > /dev/null
done
