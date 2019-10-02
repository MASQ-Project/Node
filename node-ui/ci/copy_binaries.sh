#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_EXECUTABLE="MASQNode"
DNS_EXECUTABLE="dns_utility"

if [[ "$OSTYPE" == "msys" ]]; then
  NODE_EXECUTABLEW="${NODE_EXECUTABLE}W.exe"
  NODE_EXECUTABLE="$NODE_EXECUTABLE.exe"
  DNS_EXECUTABLEW="${DNS_EXECUTABLE}w.exe"
  DNS_EXECUTABLE="$DNS_EXECUTABLE.exe"
fi

rm -rf "$CI_DIR/../src/static/binaries"
mkdir -p "$CI_DIR/../src/static/binaries"

cp "$CI_DIR/../../node/target/release/$NODE_EXECUTABLE" "$CI_DIR/../src/static/binaries/"
cp "$CI_DIR/../../dns_utility/target/release/$DNS_EXECUTABLE" "$CI_DIR/../src/static/binaries/"
if [[ "$OSTYPE" == "msys" ]]; then
  cp "$CI_DIR/../../node/target/release/$NODE_EXECUTABLEW" "$CI_DIR/../src/static/binaries/"
  cp "$CI_DIR/../../dns_utility/target/release/$DNS_EXECUTABLEW" "$CI_DIR/../src/static/binaries/"
fi
