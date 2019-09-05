#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

if [[ "$TRAVIS" == "true" ]]; then
  # No clippy on Travis CI: takes too long
  exit 0
fi

pushd "$CI_DIR/.."
cargo clippy -- -D warnings
popd
