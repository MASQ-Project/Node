#!/bin/bash -xv
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

export RUST_BACKTRACE=full
export RUSTFLAGS="-D warnings -Anon-snake-case"
cargo test --release -- --nocapture --skip _integration
