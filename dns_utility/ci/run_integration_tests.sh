#!/bin/bash -xv
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full
umask 000

cargo build --release
BUILD_RESULT=$?
chmod -R 777 "$CI_DIR/../target"
if [[ ! "$BUILD_RESULT" == "0" ]]; then
    exit "$BUILD_RESULT"
fi

cargo test --release -- _integration
