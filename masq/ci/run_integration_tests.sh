#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings"

pushd "$CI_DIR/.."
apt-get install lsof -q -y
echo "------"
echo "Here's what's using TCP:"
lsof -i4TCP
echo "------"
for i in {1..100}; do
  echo "------"
  echo "Test iteration $i"
  echo "------"
  if ! cargo test -- --nocapture --test-threads=1 handles_startup_and_shutdown_integration; then
    echo "------"
    echo "Test failure! Huzzah!"
    echo "------"
    exit 1
  fi
done
BUILD_RESULT=$?
popd
exit "$BUILD_RESULT"
