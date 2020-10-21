#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings -Anon-snake-case"
pushd "$CI_DIR/.."
cargo test --release --lib --no-fail-fast -- --nocapture --skip _integration
popd
