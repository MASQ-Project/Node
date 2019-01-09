#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

export PATH="$PATH:$HOME/.cargo/bin"

export RUST_BACKTRACE=full

# Docker-beside-Docker: Running these tests requires building and starting Docker containers that refer to an
# existing executable on the host system. If you're not running in a Docker container, the executable you want
# will be in your own filesystem, and these scripts can find everything they need without assistance.  But if you
# _are_ running in a Docker container, the containers you start will be your siblings, not your children, and the
# executable they need will not be in your filesystem but in your (and their) parent's filesystem.  If that's the
# case, make sure you pass in as parameter 1 the path to the directory just above the 'node' module directory,
# IN THE CONTEXT OF THE PARENT (host) FILESYSTEM.
export HOST_NODE_PARENT_DIR="$1"

if [ "HOST_NODE_PARENT_DIR" == "" ]; then
    export HOST_NODE_PARENT_DIR="$CI_DIR/../.."
fi

cd docker
./build.sh
cd "${CI_DIR}"/..

# TODO remove -Aproc-macro-derive-resolution-fallback when they are promoted to errors
export RUSTFLAGS="-D warnings -Anon-snake-case -Aproc-macro-derive-resolution-fallback"
cargo test --release -- --nocapture --test-threads=1
