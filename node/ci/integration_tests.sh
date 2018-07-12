#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_PARENT_DIR="$1"

if [[ "$NODE_PARENT_DIR" == "" ]]; then
    NODE_PARENT_DIR="$CI_DIR/../.."
fi

# HTTPBIN_HOME and DNS_SERVER are defined in Jenkins global properties
# Suitable defaults are HTTPBIN_HOME=httbin.org and DNS_SERVER=8.8.8.8
case "$OSTYPE" in
    msys)
        echo "Windows"
        "$CI_DIR/run_integration_tests.sh"
        ;;
    Darwin | darwin*)
        echo "macOS"
        sudo HTTPBIN_HOST=$HTTPBIN_HOST DNS_SERVER=$DNS_SERVER "$CI_DIR/run_integration_tests.sh"
        ;;
    linux-gnu)
        echo "Linux"
        sudo HTTPBIN_HOST=$HTTPBIN_HOST DNS_SERVER=$DNS_SERVER "$CI_DIR/run_integration_tests.sh"
        ;;
    *)
        exit 1
        ;;
esac
