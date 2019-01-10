#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
PASSPHRASE="$1"
NODE_EXECUTABLE="SubstratumNode"
DNS_EXECUTABLE="dns_utility"
GPG_EXECUTABLE="gpg"

if [[ "$OSTYPE" == "msys" ]]; then
  NODE_EXECUTABLE="$NODE_EXECUTABLE.exe"
  DNS_EXECUTABLE="$DNS_EXECUTABLE.exe"
  GPG_EXECUTABLE="/c/Program Files (x86)/gnupg/bin/gpg"
fi

cd "$CI_DIR/../dns_utility"
cargo clean
"ci/build.sh"

cd "$CI_DIR/../node"
cargo clean
"ci/build.sh"

# sign
"${GPG_EXECUTABLE}" --batch --passphrase "$PASSPHRASE" -b target/release/$NODE_EXECUTABLE
"${GPG_EXECUTABLE}" --verify target/release/$NODE_EXECUTABLE.sig target/release/$NODE_EXECUTABLE

# gui
cd "$CI_DIR/../node_ui"
"ci/release.sh"

cd "$CI_DIR/../"

case "$OSTYPE" in
   linux*)
        zip -j SubstratumNode-Linux64-binary.zip dns_utility/target/release/$DNS_EXECUTABLE node/target/release/$NODE_EXECUTABLE node/target/release/$NODE_EXECUTABLE.sig
        zip -j SubstratumNode-Linux64-deb.zip node_ui/dist/SubstratumNode*.deb
        ;;
   darwin*)
        zip -j SubstratumNode-macOS-binary.zip dns_utility/target/release/$DNS_EXECUTABLE node/target/release/$NODE_EXECUTABLE node/target/release/$NODE_EXECUTABLE.sig
        zip -j SubstratumNode-macOS.dmg.zip node_ui/dist/SubstratumNode*.dmg
        ;;
   msys)
        zip -j SubstratumNode-Windows-binary.zip dns_utility/target/release/$DNS_EXECUTABLE node/target/release/$NODE_EXECUTABLE node/target/release/$NODE_EXECUTABLE.sig
        zip -j SubstratumNode-Windows.exe.zip node_ui/dist/SubstratumNode*.exe
        ;;
   *)
        echo "unsupported operating system detected."; exit 1
        ;;
esac
