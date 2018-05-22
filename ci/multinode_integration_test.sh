#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

PARENT_DIR="$1"

cd "${CI_DIR}/../multinode_integration_tests"
ci/all.sh "$PARENT_DIR"
