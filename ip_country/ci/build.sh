#!/bin/bash -xev
# Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/.."
cargo build --release --verbose
popd