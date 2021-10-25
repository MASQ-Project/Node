#!/bin/bash
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mkdir -p generated

cp ../../port_exposer/target/debug/port_exposer generated/port_exposer

docker build -t test_node_image .
