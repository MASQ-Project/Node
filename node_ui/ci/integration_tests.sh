#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

case "$OSTYPE" in
    msys)
        echo "Windows"
        mkdir -p "$CI_DIR/../static/binaries/win"
        ln -fs "$CI_DIR/../../node/target/release/SubstratumNode.exe" "$CI_DIR/../static/binaries/win/"
        ;;
    Darwin | darwin*)
        echo "macOS"
            mkdir -p "$CI_DIR/../static/binaries/mac"
            ln -fs "$CI_DIR/../../node/target/release/SubstratumNode" "$CI_DIR/../static/binaries/mac/"
        ;;
    linux-gnu)
        echo "Linux"
        mkdir -p "$CI_DIR/../static/binaries/linux"
        ln -fs "$CI_DIR/../../node/target/release/SubstratumNode" "$CI_DIR/../static/binaries/linux/"
        ;;
    *)
        exit 1
        ;;
esac
yarn spec
