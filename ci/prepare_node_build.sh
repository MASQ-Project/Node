#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"

source "$CI_DIR"/environment.sh "$TOOLCHAIN_HOME"

"$CI_DIR/format.sh"
