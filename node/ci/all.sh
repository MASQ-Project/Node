#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_PARENT_DIR="$1"

export RUSTC_WRAPPER=sccache
pushd "$CI_DIR/.."
ci/lint.sh
ci/unit_tests.sh
ci/integration_tests.sh "$NODE_PARENT_DIR"
popd
