#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full

pushd "$CI_DIR/../../port_exposer"
ci/all.sh "$TOOLCHAIN_HOME"
popd

pushd "$CI_DIR/../docker/blockchain"
./build.sh
popd

case "$OSTYPE" in
    Darwin | darwin*)
        echo "macOS"
        pushd "$CI_DIR/../docker/macos/"
        ./build.sh
        popd
        ;;
    *)
        ;;
esac

pushd ./docker
./build.sh
popd

pushd "$CI_DIR/.."
export RUSTFLAGS="-D warnings -Anon-snake-case"
ci/lint.sh
cargo test --release -- --nocapture --test-threads=1
popd
