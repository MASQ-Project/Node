#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
NODE_BASE_DIR="$1"

cd "$CI_DIR/../sub_lib"
ci/all.sh "$NODE_BASE_DIR"
cd "$CI_DIR/../entry_dns_lib"
ci/all.sh "$NODE_BASE_DIR"
cd "$CI_DIR/../neighborhood_lib"
ci/all.sh "$NODE_BASE_DIR"
cd "$CI_DIR/../hopper_lib"
ci/all.sh "$NODE_BASE_DIR"
cd "$CI_DIR/../proxy_server"
ci/all.sh "$NODE_BASE_DIR"
cd "$CI_DIR/../proxy_client"
ci/all.sh "$NODE_BASE_DIR"
cd "$CI_DIR/../node"
ci/all.sh "$NODE_BASE_DIR"
