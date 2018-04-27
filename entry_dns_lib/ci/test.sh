#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
pkill -f SubstratumNode$ || echo "shouldn't matter whether pkill succeeds"
export RUST_BACKTRACE=full
cargo test --release -- --nocapture
