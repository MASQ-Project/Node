#!/bin/bash -xv
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

if [ "$OS" != "Windows_NT" ]; then
    # Under Windows, the node process is not persistent; therefore we don't have to kill it
    pkill node
fi

export RUST_BACKTRACE=full
cargo test -- --nocapture --test-threads=1
