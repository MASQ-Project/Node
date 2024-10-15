#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings"

pushd "$CI_DIR/.."
cargo test --release -- --nocapture --test-threads=1 "_integration"
BUILD_RESULT=$?
popd
exit "$BUILD_RESULT"
