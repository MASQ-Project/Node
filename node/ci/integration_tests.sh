#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_PARENT_DIR="$1"

if [[ "$NODE_PARENT_DIR" == "" ]]; then
    NODE_PARENT_DIR="$CI_DIR/../.."
fi

case "$OSTYPE" in
    msys)
        echo "Windows"
        "$CI_DIR/run_integration_tests.sh"
        ;;
    Darwin | darwin*)
        echo "macOS"
        sudo "$CI_DIR/run_integration_tests.sh"
        ;;
    linux-gnu)
        echo "Linux"
        cd "$CI_DIR/../docker/integration_tests"

        echo "Path: $PATH"
        docker build -t node_integration_test .

        echo "NODE_BASE_DIR: $NODE_PARENT_DIR"
        echo "Contents:"
        echo $(ls "$NODE_PARENT_DIR")
        docker run -v "$NODE_PARENT_DIR":/node_root -t node_integration_test
        ;;
    *)
        exit 1
        ;;
esac
