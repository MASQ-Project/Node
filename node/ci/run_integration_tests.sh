#!/bin/bash -xv
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings -Anon-snake-case"
umask 000

pushd "$CI_DIR/.."
cargo test --release --no-fail-fast -- --nocapture --test-threads=1 _integration
BUILD_RESULT=$?
chmod -R 777 target
popd
exit "$BUILD_RESULT"
