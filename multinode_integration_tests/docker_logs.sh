#!/bin/bash -xv

CONTAINER_NAME="$1"
docker start "$CONTAINER_NAME"
docker cp "$CONTAINER_NAME":/tmp/SubstratumNode.log /tmp/"$CONTAINER_NAME".log
cat "/tmp/$CONTAINER_NAME".log
