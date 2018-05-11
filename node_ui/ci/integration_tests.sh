#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

if [[ "$OSTYPE" == "msys" ]]; then
    echo "Windows"
    mkdir -p "$CI_DIR/../static/binaries/win"
    ln -fs "$CI_DIR/../../node/target/release/SubstratumNode.exe" "$CI_DIR/../static/binaries/win/"
else
    echo "Not Windows"
    mkdir -p "$CI_DIR/../static/binaries/linux"
    ln -fs "$CI_DIR/../../node/target/release/SubstratumNode" "$CI_DIR/../static/binaries/linux/"
    # When we fix the problem described in node/ci/all.sh, bring these lines back
#    mkdir -p "$CI_DIR/../static/binaries/mac"
#    ln -fs "$CI_DIR/../../node/target/release/SubstratumNode" "$CI_DIR/../static/binaries/mac/"
fi
yarn spec
