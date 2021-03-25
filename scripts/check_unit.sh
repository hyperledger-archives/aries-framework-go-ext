#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

unit_tests_path=$1
if [ -z "$unit_tests_path" ]; then
  unit_tests_path="${UNIT_TESTS_PATH}"
fi

if [ -z "$unit_tests_path" ]; then
  unit_tests_path=./
fi

if [ -z "${EXCLUDE_TEST_PATH}" ]; then
  exclude=""
else
  exclude="-path ${EXCLUDE_TEST_PATH} -prune -o"
fi

coverage_path="$(pwd)/coverage.out"
rm -f "$coverage_path"

function clean ()
{
  rm -f "$(pwd)/profile.out"
}

trap exit INT
trap clean EXIT

for i in $(find $unit_tests_path -path ./test -prune -o $exclude -name "go.mod" -print)
do
  pushd "$(dirname $i)" > /dev/null
  if [ -z $(go list) ]; then
      popd  > /dev/null
      continue
  fi
  go test -count=1 -race -coverprofile=profile.out -covermode=atomic ./... -timeout=10m
    cat profile.out  >> "$coverage_path"
  clean
  popd  > /dev/null
done
