#!/bin/bash

set -e

MODULES=(
  dns_utility
  masq
  node
)

os="$1"

for module in "${MODULES[@]}"; do
  echo "Running integration tests for $module on $os..."
  pushd ./"$module"/ci
  ./integration_tests.sh
  popd
done
