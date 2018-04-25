#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_PARENT_DIR="$1"

"$CI_DIR/clean.sh"
"$CI_DIR/build.sh"
"$CI_DIR/unit_tests.sh"
"$CI_DIR/integration_tests.sh" "$NODE_PARENT_DIR"
