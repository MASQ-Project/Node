#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

"$CI_DIR/../node_modules/.bin/node-sass" "$CI_DIR/../assets/styles/main.scss" "$CI_DIR/../assets/styles/main.css" -r --output-style compact