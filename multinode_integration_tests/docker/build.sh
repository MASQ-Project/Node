#!/bin/bash
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mkdir -p generated

cp ../../port_exposer/target/debug/port_exposer generated/port_exposer

docker build -t test_node_image .
