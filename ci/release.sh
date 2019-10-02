#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"
NODE_EXECUTABLE="SubstratumNode"
DNS_EXECUTABLE="dns_utility"
GPG_EXECUTABLE="gpg"

if [[ "$PASSPHRASE" == "" ]]; then
  echo "PASSPHRASE cannot be blank"
  exit 1
fi

if [[ "$OSTYPE" == "msys" ]]; then
  NODE_EXECUTABLEW="${NODE_EXECUTABLE}W.exe"
  NODE_EXECUTABLE="$NODE_EXECUTABLE.exe"
  DNS_EXECUTABLEW="${DNS_EXECUTABLE}W.exe"
  DNS_EXECUTABLE="$DNS_EXECUTABLE.exe"
  GPG_EXECUTABLE="/c/Program Files (x86)/gnupg/bin/gpg"
fi

source "$CI_DIR"/environment.sh "$TOOLCHAIN_HOME"

cd "$CI_DIR/../node"
cargo clean
"ci/build.sh"

cd "$CI_DIR/../dns_utility"
cargo clean
"ci/build.sh"

function azure_key_vault_sign() {
	for file in "$@"; do
		AzureSignTool sign "$file" \
		--file-digest sha256 \
		--timestamp-rfc3161 http://timestamp.digicert.com \
		--timestamp-digest sha256 \
		--azure-key-vault-url https://substratumnode.vault.azure.net \
		--azure-key-vault-client-id "77cb9689-ce27-412f-bc16-4cc0a599676b" \
		--azure-key-vault-client-secret "$AZURE_KEY_VAULT_CLIENT_SECRET" \
		--azure-key-vault-certificate "SubstratumNodeCodeSinging"
	done
}

# sign
case "$OSTYPE" in
   linux*)
      cd "$CI_DIR/../node"
      "${GPG_EXECUTABLE}" --batch --passphrase "$PASSPHRASE" -b target/release/$NODE_EXECUTABLE
      "${GPG_EXECUTABLE}" --verify target/release/$NODE_EXECUTABLE.sig target/release/$NODE_EXECUTABLE
      cd "$CI_DIR/../dns_utility"
      "${GPG_EXECUTABLE}" --batch --passphrase "$PASSPHRASE" -b target/release/$DNS_EXECUTABLE
      "${GPG_EXECUTABLE}" --verify target/release/$DNS_EXECUTABLE.sig target/release/$DNS_EXECUTABLE
      ;;
   darwin*)
      security unlock-keychain -p "$PASSPHRASE"
      cd "$CI_DIR/../node"
      codesign -s 'Developer ID Application: Substratum Services, Inc. (TKDGR66924)' -i 'net.substratum.substratumnode' -fv "target/release/$NODE_EXECUTABLE"
      codesign -v -v "target/release/$NODE_EXECUTABLE"
      cd "$CI_DIR/../dns_utility"
      codesign -s 'Developer ID Application: Substratum Services, Inc. (TKDGR66924)' -i 'net.substratum.dns-utility' -fv "target/release/$DNS_EXECUTABLE"
      codesign -v -v "target/release/$DNS_EXECUTABLE"
      ;;
   msys)
      if [[ "$AZURE_KEY_VAULT_CLIENT_SECRET" == "" ]]; then
        echo "AZURE_KEY_VAULT_CLIENT_SECRET cannot be blank"
        exit 1
      fi
      cd "$CI_DIR/../node"
      azure_key_vault_sign "target/release/$NODE_EXECUTABLE"
      azure_key_vault_sign "target/release/$NODE_EXECUTABLEW"
      cd "$CI_DIR/../dns_utility"
      azure_key_vault_sign "target/release/$DNS_EXECUTABLE"
      azure_key_vault_sign "target/release/$DNS_EXECUTABLEW"
      ;;
   *)
        echo "unsupported operating system detected."; exit 1
   ;;
esac

# gui
cd "$CI_DIR/../node-ui"
"ci/release.sh"

cd "$CI_DIR/../"

case "$OSTYPE" in
   linux*)
        zip -j SubstratumNode-Linux64-binary.zip \
          dns_utility/target/release/$DNS_EXECUTABLE dns_utility/target/release/$DNS_EXECUTABLE.sig \
          node/target/release/$NODE_EXECUTABLE node/target/release/$NODE_EXECUTABLE.sig
        zip -j SubstratumNode-Linux64-deb.zip node-ui/electron-builder-out/SubstratumNode*.deb
        ;;
   darwin*)
        zip -j SubstratumNode-macOS-binary.zip \
          dns_utility/target/release/$DNS_EXECUTABLE \
          node/target/release/$NODE_EXECUTABLE
        zip -j SubstratumNode-macOS.dmg.zip node-ui/electron-builder-out/SubstratumNode*.dmg
        ;;
   msys)
        azure_key_vault_sign "node-ui/electron-builder-out/"SubstratumNode*.exe

        ARCHIVE_PATH="$PWD"
        pushd dns_utility/target/release
        7z a "$ARCHIVE_PATH"/SubstratumNode-Windows-binary.zip $DNS_EXECUTABLE
        7z a "$ARCHIVE_PATH"/SubstratumNode-Windows-binary.zip $DNS_EXECUTABLEW
        popd
        pushd node/target/release
        7z a "$ARCHIVE_PATH"/SubstratumNode-Windows-binary.zip $NODE_EXECUTABLEW
        popd
        pushd node-ui/electron-builder-out
        7z a "$ARCHIVE_PATH"/SubstratumNode-Windows.exe.zip SubstratumNode*.exe
        popd
        ;;
   *)
        echo "unsupported operating system detected."; exit 1
        ;;
esac
