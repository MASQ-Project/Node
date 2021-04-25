#!/bin/bash -xev
# Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings"
pushd "$CI_DIR/.."
if [ -t 0 ] && [ -t 1 ]; then
  export MASQ_TESTS_RUN_IN_TERMINAL=true
fi
cargo test --release -- --nocapture --skip _integration #--test-threads=1
popd
