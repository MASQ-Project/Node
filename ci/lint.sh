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
  echo "Running lint for $module on $os..."
  pushd ./"$module"/ci
  ./lint.sh
  popd
done
