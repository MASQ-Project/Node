#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/.."
cargo build --all --lib --bins --release --verbose --features masq_lib/no_test_share
popd
