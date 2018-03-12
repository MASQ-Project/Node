#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
REPO_BASE_DIR="$1"

if [[ "$REPO_BASE_DIR" == "" ]]; then
    REPO_BASE_DIR="$CI_DIR/../.."
fi

if [[ "$OSTYPE" == "msys" ]]; then
    echo "Windows"
    "$CI_DIR/run_integration_tests.sh"
else
    echo "Not Windows"
    cd "$CI_DIR/../docker/integration_tests"

    echo "Path: $PATH"
    docker build -t node_integration_test .

    echo $(ls "$CI_DIR/..")
    docker run -v "$REPO_BASE_DIR":/node_root -t node_integration_test
fi
