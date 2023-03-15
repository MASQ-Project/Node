#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

function init_for_linux() {
  sudo apt-get install -q -y net-tools
  common
}

function init_for_macOS() {
  common
}

function init_for_windows() {
  common
}

function common() {
  rustup show
  rustup update stable
  rustup show
  rustup component add rustfmt
  rustup component add clippy
}

case "$OSTYPE" in
  msys)
    init_for_windows
    ;;
  Darwin | darwin*)
    init_for_macOS
    ;;
  linux*)
    init_for_linux
    ;;
  *)
    echo "Unrecognized operating system $OSTYPE"
    exit 1
    ;;
esac
