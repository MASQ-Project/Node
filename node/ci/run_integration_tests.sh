#!/bin/bash -xv
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings -Anon-snake-case"
umask 000

if [ "$1" == "" ]; then
  TEST_NAME_FRAGMENT="_integration"
else
  if [[ "$USER" != "root" ]]; then
    echo "run_integration_tests.sh must be run as root"
    exit 1
  fi
  TEST_NAME_FRAGMENT="$1"
fi

pushd "$CI_DIR/.." || { echo "Failed to pushd $CI_DIR/.."; exit 1; }
cargo test --release --no-fail-fast -- --nocapture --test-threads=1 "$TEST_NAME_FRAGMENT"
BUILD_RESULT=$?
chmod -R 777 target
popd || { echo "Failed to popd"; exit 1; }
exit "$BUILD_RESULT"
