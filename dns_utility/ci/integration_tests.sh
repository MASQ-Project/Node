#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"

pushd "$CI_DIR/.."

export PATH="$PATH:$HOME/.cargo/bin"

export RUSTFLAGS="-D warnings -Anon-snake-case"
cargo test --no-run --release -- --nocapture "_integration"

case "$OSTYPE" in
    msys)
        echo "Windows"
        ci/run_integration_tests.sh sudo "$TOOLCHAIN_HOME"
        ci/run_integration_tests.sh user "$TOOLCHAIN_HOME"
        ;;
    Darwin | darwin*)
        echo "macOS"
        sudo --preserve-env ci/run_integration_tests.sh sudo "$TOOLCHAIN_HOME"
        ci/run_integration_tests.sh user "$TOOLCHAIN_HOME"
        ;;
    linux-gnu)
        echo "Linux"
        sudo --preserve-env ci/run_integration_tests.sh sudo "$TOOLCHAIN_HOME"
        ci/run_integration_tests.sh user "$TOOLCHAIN_HOME"
        ;;
    *)
        exit 1
        ;;
esac
popd
