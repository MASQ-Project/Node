#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
DNS_UTILITY_PARENT_DIR="$1"

if [[ "$DNS_UTILITY_PARENT_DIR" == "" ]]; then
    DNS_UTILITY_PARENT_DIR="$CI_DIR/../.."
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
        docker build -t integration_test .

        echo "NODE_BASE_DIR: $DNS_UTILITY_PARENT_DIR"
        echo "Contents:"
        echo $(ls "$DNS_UTILITY_PARENT_DIR")
        docker run -v "$DNS_UTILITY_PARENT_DIR":/test_root -t integration_test
        ;;
    *)
        exit 1
        ;;
esac
