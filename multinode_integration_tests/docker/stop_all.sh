#!/bin/bash -xv
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

docker ps -q --filter ancestor=test_node_image | xargs docker stop -t 01
