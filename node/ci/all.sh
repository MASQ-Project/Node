#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_PARENT_DIR="$1"

"$CI_DIR/clean.sh"
"$CI_DIR/build.sh"
"$CI_DIR/unit_tests.sh"

# These lines can be removed once we fix the problem below
if [[ "$OSTYPE" != "msys" ]]; then
    mkdir -p "$CI_DIR/../../node_ui/static/binaries/mac"
    cp "$CI_DIR/../../node/target/release/SubstratumNode" "$CI_DIR/../../node_ui/static/binaries/mac/"
fi

# WARNING: After running the integration tests, the resulting executable WILL NOT WORK on MacOS!!
# ( The integration tests run in a docker which rebuilds the executable for Linux, overwriting the one correctly built for mac )
"$CI_DIR/integration_tests.sh" "$NODE_PARENT_DIR"
