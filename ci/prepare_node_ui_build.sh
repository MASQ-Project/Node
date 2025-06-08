#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

"$CI_DIR/../node-ui/ci/setup.sh"
"$CI_DIR/../node-ui/ci/lint.sh"
