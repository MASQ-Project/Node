#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
export RUST_BACKTRACE=full
# TODO remove -Aproc-macro-derive-resolution-fallback when they are promoted to errors
export RUSTFLAGS="-D warnings -Anon-snake-case -Aproc-macro-derive-resolution-fallback"
cargo test --release -- --nocapture
