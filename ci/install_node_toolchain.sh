#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

if [[ "$1" == "" ]]; then
  CACHE_TARGET="$HOME"
else
  CACHE_TARGET="$1"
fi

if [[ "$2" == "" ]]; then
  RUST_VERSION="stable"
else
  RUST_VERSION="$2"
fi

RUSTUP="$HOME/.cargo/bin/rustup"
CARGO="$HOME/.cargo/bin/cargo"

function install_linux_macOS() {
  rm -r "$HOME/.cargo" || echo "Rust cargo not installed on $OSTYPE"
  rm -r "$HOME/.rustup" || echo "Rust rustup not installed on $OSTYPE"
  curl https://sh.rustup.rs -sSf | bash -s -- -y
  common
}

function install_windows() {
  CACHE_TARGET="$("$CI_DIR"/bashify_workspace.sh "$CACHE_TARGET")"
  rm -r "$HOME/.cargo"
  rm -r "$HOME/.rustup"
  curl https://win.rustup.rs -sSf > /tmp/rustup-init.exe
  /tmp/rustup-init.exe -y
  common
}

function common() {
  "$RUSTUP" update
  "$RUSTUP" install "$RUST_VERSION"
  "$RUSTUP" default "$RUST_VERSION"
  "$RUSTUP" component add rustfmt
  "$RUSTUP" component add clippy
  "$CARGO" install sccache

  mkdir -p "$CACHE_TARGET/toolchains"
  cp -pR "$HOME/.cargo" "$CACHE_TARGET"/toolchains/.cargo
  chmod +x "$CACHE_TARGET"/toolchains/.cargo/bin/*
  cp -pR "$HOME/.rustup" "$CACHE_TARGET"/toolchains/.rustup
}

function build_tiny() {
  cd $CI_DIR/../port_exposer
  "$CARGO" fmt
  "$CARGO" check
  "$CARGO" clippy
  "$CARGO" build
}

case "$OSTYPE" in
  msys)
    install_windows
    ;;
  Darwin | darwin*)
    install_linux_macOS
    ;;
  linux*)
    install_linux_macOS
    ;;
  *)
    echo "Unrecognized operating system $OSTYPE"
    exit 1
    ;;
esac

# Build a tiny project to make sure the toolchain is all built and ready to cache
build_tiny
