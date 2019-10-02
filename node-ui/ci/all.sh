#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/.."
ci/setup.sh
ci/lint.sh
ci/unit_tests.sh
ci/build.sh
ci/integration_tests.sh
popd
