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
  echo "Building $module on $os..."
  pushd ./"$module"/ci
  ./build.sh
  popd
done
