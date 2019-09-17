#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/.."
# So far, allowed lints are tech debt to be addressed later.
# They are ordered roughly by number of occurrences descending.
cargo clippy -- -D warnings -Anon-snake-case \
    -A clippy::ptr_arg \
    -A clippy::char_lit_as_u8 \
    -A clippy::match_wild_err_arm \
    -A clippy::needless_range_loop \
    -A clippy::too_many_arguments \
    -A clippy::wrong_self_convention \
    -A clippy::clone_double_ref \
    -A clippy::derive_hash_xor_eq \
    -A clippy::cognitive_complexity
popd
