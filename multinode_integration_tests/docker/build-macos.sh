#!/bin/bash
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CI_DIR="$(cd "$(dirname "$0")" && pwd)"
echo $CI_DIR
echo $BASE_DIR

mkdir -p generated

cp ../../port_exposer/target/debug/port_exposer generated/port_exposer

docker container rm macos-builder-image
docker build -t macos-builder-image .
docker run -d --name macos-builder -v $BASE_DIR:/node/ --workdir /node/ --entrypoint ./ci/all.sh macos-builder-image
