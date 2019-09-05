#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

NODE_BINARY="$(which node)"
NODE_DIR="$(dirname "$NODE_BINARY")"

function run_on_linux() {
  xvfb-run -a -e /tmp/xvfb.out -s "-screen 0 1024x768x8" sudo -E PATH="$PATH:$NODE_DIR" ci/run_integration_tests.sh
}

function run_on_macOS() {
  sudo -E PATH="$PATH:$NODE_DIR" ci/run_integration_tests.sh
}

function run_on_windows() {
  ci/run_integration_tests.sh
}

pushd "$CI_DIR/.."
case "$OSTYPE" in
  msys)
    run_on_windows
    ;;
  Darwin | darwin*)
    run_on_macOS
    ;;
  linux*)
    run_on_linux
    ;;
  *)
    exit 1
    ;;
esac
popd
