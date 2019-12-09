#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/.."
cargo build --release --verbose
popd