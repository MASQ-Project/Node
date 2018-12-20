#!/bin/bash -xv
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

cd "$CI_DIR"/../node

if [[ "$WINDIR" == "" ]]; then
    cargo fmt --all --quiet -- --check
    exit_code="$?"
    cargo fmt --all
    exit "$exit_code"
fi
