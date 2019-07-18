#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
PASSPHRASE="$1"
NODE_EXECUTABLE="SubstratumNode"
DNS_EXECUTABLE="dns_utility"
GPG_EXECUTABLE="gpg"

if [[ "$OSTYPE" == "msys" ]]; then
  NODE_EXECUTABLEW="${NODE_EXECUTABLE}W.exe"
  NODE_EXECUTABLE="$NODE_EXECUTABLE.exe"
  DNS_EXECUTABLEW="${DNS_EXECUTABLE}W.exe"
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
if [[ "$OSTYPE" == "msys" ]]; then
  "${GPG_EXECUTABLE}" --batch --passphrase "$PASSPHRASE" -b target/release/$NODE_EXECUTABLEW
  "${GPG_EXECUTABLE}" --verify target/release/$NODE_EXECUTABLEW.sig target/release/$NODE_EXECUTABLEW
fi

# gui
cd "$CI_DIR/../node-ui"
"ci/release.sh"

cd "$CI_DIR/../"

case "$OSTYPE" in
   linux*)
        zip -j SubstratumNode-Linux64-binary.zip dns_utility/target/release/$DNS_EXECUTABLE node/target/release/$NODE_EXECUTABLE node/target/release/$NODE_EXECUTABLE.sig
        zip -j SubstratumNode-Linux64-deb.zip node-ui/electron-builder-out/SubstratumNode*.deb
        ;;
   darwin*)
        zip -j SubstratumNode-macOS-binary.zip dns_utility/target/release/$DNS_EXECUTABLE node/target/release/$NODE_EXECUTABLE node/target/release/$NODE_EXECUTABLE.sig
        zip -j SubstratumNode-macOS.dmg.zip node-ui/electron-builder-out/SubstratumNode*.dmg
        ;;
   msys)
        zip -j SubstratumNode-Windows-binary.zip dns_utility/target/release/$DNS_EXECUTABLE dns_utility/target/release/$DNS_EXECUTABLEW node/target/release/$NODE_EXECUTABLE node/target/release/$NODE_EXECUTABLEW node/target/release/$NODE_EXECUTABLE.sig node/target/release/$NODE_EXECUTABLEW.sig
        zip -j SubstratumNode-Windows.exe.zip node-ui/electron-builder-out/SubstratumNode*.exe
        ;;
   *)
        echo "unsupported operating system detected."; exit 1
        ;;
esac
