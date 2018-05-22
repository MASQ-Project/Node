#!/bin/bash
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CONTAINER_NAME=$1

docker stop -t 0 "${CONTAINER_NAME}"
