#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/.."
ci/copy_binaries.sh
popd
pushd "$CI_DIR/../render-process"
yarn build
popd
pushd "$CI_DIR/../main-process"
chmod +x dist/static/**/*
popd
