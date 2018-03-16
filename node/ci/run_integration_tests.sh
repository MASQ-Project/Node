#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export RUST_BACKTRACE=full
if [[ -e "$CI_DIR/../target/release/node" ]]; then
    chmod -R 777 "$CI_DIR/../target/release"
else
    echo "Can't run integration tests; must build release version first"
    exit 1
fi

cargo test -- _integration
