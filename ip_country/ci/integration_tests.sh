#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"

pushd "$CI_DIR/.."
ci/build.sh # Build here before sudo to make sure we don't produce any root-owned object files
case "$OSTYPE" in
    msys)
        echo "Windows"
        ci/run_integration_tests.sh "$TOOLCHAIN_HOME"
        ;;
    Darwin | darwin*)
        echo "macOS"
        sudo --preserve-env ci/run_integration_tests.sh "$TOOLCHAIN_HOME"
        ;;
    linux-gnu)
        echo "Linux"
        sudo --preserve-env ci/run_integration_tests.sh "$TOOLCHAIN_HOME"
        ;;
    *)
        exit 1
        ;;
esac
popd
