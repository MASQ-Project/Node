#!/bin/bash -xv
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
KIND="$1" # should be either 'sudo' or 'user'

export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full
# TODO remove -Aproc-macro-derive-resolution-fallback when they are promoted to errors
export RUSTFLAGS="-D warnings -Anon-snake-case -Aproc-macro-derive-resolution-fallback"
umask 000

cargo test --release -- --nocapture "_${KIND}_integration"
BUILD_RESULT=$?
if [[ "$(id -u)" == "0" ]]; then
    chmod -R 777 "$CI_DIR/../target"
fi
exit "$BUILD_RESULT"
