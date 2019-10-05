#!/usr/bin/env bash
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/../main-process" || exit 1
yarn start
popd || exit 1
