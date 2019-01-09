#!/bin/bash -xv
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

cd "$CI_DIR"/../node

cargo fmt --all -- --check
exit_code="$?"
if [[ "$exit_code" != "0" ]]; then
    echo "Your code failed the formatting check. If you wish to leave the code the way it is, use the directive #[cfg_attr(rustfmt, rustfmt_skip)]"
fi
cargo fmt --all
exit "$exit_code"
