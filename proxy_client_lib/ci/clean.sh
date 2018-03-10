#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

rm "$CI_DIR"/../Cargo.lock || echo "Cargo.lock is already gone"
touch "$CI_DIR"/../Cargo.toml
cargo clean
