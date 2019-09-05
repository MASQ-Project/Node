#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

mkdir -p "$CI_DIR/../results"
pushd "$CI_DIR/../results"
sudo rm -rf generated
mkdir generated
sudo cp -R ../node/generated generated/node || echo "No results from SubstratumNode"
cp -R ../dns_utility/generated generated/dns_utility || echo "No results from dns_utility"
cp -R ../multinode_integration_tests/generated generated/multinode_integration_tests || echo "No results from multinode integration tests"
cp -R ../node-ui/generated generated/node-ui || echo "No results from SubstratumNode UI"
cp -R ../node-ui/dist generated/dist || echo "No distributable binaries"
sudo zip -r generated.zip generated/*
popd
