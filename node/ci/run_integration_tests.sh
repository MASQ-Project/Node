#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export RUST_BACKTRACE=full
chmod -R 777 "$CI_DIR/../target" || echo "No target directory exists"
if [[ ! -e "$CI_DIR/../target/release/node" ]]; then
    echo "Can't run integration tests; must build release version first. Try ci/build.sh"
    exit 1
fi

cargo test -- _integration
