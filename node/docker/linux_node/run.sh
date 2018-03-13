#!/bin/bash -xev
docker run -ti --rm --cap-add=NET_ADMIN --name linux_node -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v "$(pwd)"/../../target/release:/node linux_node
