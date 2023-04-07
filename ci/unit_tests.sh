#!/bin/bash

set -e

MODULES=(
  automap
  dns_utility
  masq
  masq_lib
  node
)

os="$1"

for module in "${MODULES[@]}"; do
  echo "Running unit tests for $module on $os..."
  pushd ./"$module"/ci
  ./unit_tests.sh
  popd
done
