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
  "$HOME/.cargo/bin/rustup" update
  "$HOME/.cargo/bin/rustup" install "$RUST_VERSION"
  "$HOME/.cargo/bin/rustup" default "$RUST_VERSION"
  "$HOME/.cargo/bin/rustup" component add rustfmt
  "$HOME/.cargo/bin/rustup" component add clippy
  "$HOME/.cargo/bin/cargo" install sccache

  mkdir -p "$CACHE_TARGET/toolchains"
  cp -pR "$HOME/.cargo" "$CACHE_TARGET"/toolchains/.cargo
  chmod +x "$CACHE_TARGET"/toolchains/.cargo/bin/*
  cp -pR "$HOME/.rustup" "$CACHE_TARGET"/toolchains/.rustup
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
