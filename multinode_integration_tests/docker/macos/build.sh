#!/bin/bash -evx
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
BASE_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
CI_DIR="$(cd "$(dirname "$0")" && pwd)"
echo $CI_DIR
echo $BASE_DIR

docker container rm -f macos-builder || continue
docker build --build-arg uid=$(id -u) --build-arg gid=$(id -g) -t macos-builder-image .
docker run --rm --name macos-builder --user $(id -u):$(id -g) -v "$BASE_DIR":/usr/src -w /usr/src/dns_utility macos-builder-image ci/build.sh
docker run --rm --name macos-builder --user $(id -u):$(id -g) -v "$BASE_DIR":/usr/src -w /usr/src/port_exposer macos-builder-image ci/all.sh
docker run --rm --name macos-builder --user $(id -u):$(id -g) -v "$BASE_DIR":/usr/src -w /usr/src/node macos-builder-image ci/build.sh
