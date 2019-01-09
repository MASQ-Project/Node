#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
DNS_UTILITY_PARENT_DIR="$1"

"$CI_DIR/unit_tests.sh"
"$CI_DIR/integration_tests.sh" "$DNS_UTILITY_PARENT_DIR"
