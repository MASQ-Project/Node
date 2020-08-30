#!/bin/bash -xev
# Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"

export PATH="$PATH:$HOME/.cargo/bin"
source "$CI_DIR"/../../ci/environment.sh "$TOOLCHAIN_HOME"

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings"

pushd "$CI_DIR/.."
cargo test --release -- --nocapture --test-threads=1 "_integration"
BUILD_RESULT=$?
popd
exit "$BUILD_RESULT"
