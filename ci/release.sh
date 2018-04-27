#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
PASSPHRASE="$1"
EXECUTABLE="SubstratumNode"

if [[ "$OSTYPE" == "msys" ]]; then
  EXECUTABLE="$EXECUTABLE.exe"
fi

cd "$CI_DIR/../node"
"ci/clean.sh"
"ci/build.sh"

# sign
gpg --pinentry-mode loopback --passphrase "$PASSPHRASE" -b target/release/$EXECUTABLE
gpg --verify target/release/$EXECUTABLE.sig target/release/$EXECUTABLE
