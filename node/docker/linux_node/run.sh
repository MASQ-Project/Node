#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
docker run -ti --rm --cap-add=NET_ADMIN --name linux_node -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v "$(pwd)"/../../target/release:/node linux_node
