#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
DNS_UTILITY_PARENT_DIR="$1"

if [[ "$DNS_UTILITY_PARENT_DIR" == "" ]]; then
    DNS_UTILITY_PARENT_DIR="$CI_DIR/../.."
fi

pushd "$CI_DIR/.."
case "$OSTYPE" in
    msys)
        echo "Windows"
        ci/run_integration_tests.sh sudo
        ci/run_integration_tests.sh user
        ;;
    Darwin | darwin*)
        echo "macOS"
        sudo ci/run_integration_tests.sh sudo
        ci/run_integration_tests.sh user
        ;;
    linux-gnu)
        echo "Linux"
        sudo ci/run_integration_tests.sh sudo
        ci/run_integration_tests.sh user
        ;;
    *)
        exit 1
        ;;
esac
popd
