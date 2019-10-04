#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_EXECUTABLE="SubstratumNode"
DNS_EXECUTABLE="dns_utility"

if [[ "$OSTYPE" == "msys" ]]; then
  NODE_EXECUTABLEW="${NODE_EXECUTABLE}W.exe"
  NODE_EXECUTABLE="$NODE_EXECUTABLE.exe"
  DNS_EXECUTABLEW="${DNS_EXECUTABLE}w.exe"
  DNS_EXECUTABLE="$DNS_EXECUTABLE.exe"
fi

BINARIES_DIR="$CI_DIR/../render-process/src/static/binaries/"

rm -rf "$BINARIES_DIR"
mkdir -p "$BINARIES_DIR"

cp "$CI_DIR/../../node/target/release/$NODE_EXECUTABLE" "$BINARIES_DIR"
cp "$CI_DIR/../../dns_utility/target/release/$DNS_EXECUTABLE" "$BINARIES_DIR"
if [[ "$OSTYPE" == "msys" ]]; then
  cp "$CI_DIR/../../node/target/release/$NODE_EXECUTABLEW" "$BINARIES_DIR"
  cp "$CI_DIR/../../dns_utility/target/release/$DNS_EXECUTABLEW" "$BINARIES_DIR"
fi
