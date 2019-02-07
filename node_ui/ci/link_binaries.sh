#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_EXECUTABLE="SubstratumNode"
DNS_EXECUTABLE="dns_utility"

if [[ "$OSTYPE" == "msys" ]]; then
  NODE_EXECUTABLE="$NODE_EXECUTABLE.exe"
  DNS_EXECUTABLE="$DNS_EXECUTABLE.exe"
fi

rm -rf "$CI_DIR/../static/binaries"
mkdir -p "$CI_DIR/../static/binaries"

cp "$CI_DIR/../../node/target/release/$NODE_EXECUTABLE" "$CI_DIR/../static/binaries/"
cp "$CI_DIR/../../dns_utility/target/release/$DNS_EXECUTABLE" "$CI_DIR/../static/binaries/"
