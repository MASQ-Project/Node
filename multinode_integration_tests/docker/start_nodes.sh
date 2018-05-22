#!/bin/bash
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

DOCKER_DIR="$( cd "$( dirname "$0" )" && pwd )"

PORT_LISTS=$@
STARTUP_RETRY_MAX=5
CONTAINER_INDEX=1

# Docker-beside-Docker: Running this script requires building and starting Docker containers that refer to an
# existing executable on the host system. If you're not running in a Docker container, the executable you want
# will be in your own filesystem, and this script can find everything it needs without assistance.  But if you
# _are_ running in a Docker container (for example, subjenkins), the containers you start will be your siblings,
# not your children, and the executable they need will not be in your filesystem but in your (and their) parent's
# filesystem.  If that's the case, make sure you set in the HOST_NODE_PARENT_DIR environment variable the path to
# the directory just above the 'node' module directory, IN THE CONTEXT OF THE PARENT (host) FILESYSTEM.

if [ "$HOST_NODE_PARENT_DIR" == "" ]; then
    COMMAND_DIR="$DOCKER_DIR/../../node/target/release"
else
    COMMAND_DIR="$HOST_NODE_PARENT_DIR/node/target/release"
fi

function wait_for_startup() {
    local IP="$1"
    local RETRIES_REMAINING="$STARTUP_RETRY_MAX"
    while [ 0 == 0 ]; do
        if [ "$RETRIES_REMAINING" == "0" ]; then
            echo "$IP didn't start"
            return 1
        fi
        nc -z -w1 "$IP" 80
        local RUN_RESULT="$?"
        if [ "$RUN_RESULT" == "0" ]; then
            echo "Successful start detected for $IP"
            return 0
        fi
        echo "Still waiting for $IP to start"
        ((RETRIES_REMAINING-=1))
    done
}

function start_node() {
    local INDEX="$1"
    local PORT_LIST="$2"
    local CONTAINER_IP="172.18.1.$INDEX"
    local CONTAINER_NAME="test_node_$INDEX"
    echo "Initiating start of $CONTAINER_NAME on $CONTAINER_IP"
    docker run --ip "$CONTAINER_IP" --dns 127.0.0.1 --rm --name "$CONTAINER_NAME" --net integration_net -v "$COMMAND_DIR":/node_root/node test_node_image &
    local RUN_RESULT=$?
    if [ "$RUN_RESULT" != "0" ]; then
        return 1
    fi
    wait_for_startup "$CONTAINER_IP"
}

function kill_containers_up_to() {
    local LIMIT="$1"
    for INDEX in $(seq 1 "$LIMIT"); do
        CONTAINER_NAME="test_node_$INDEX"
        docker stop -t 0 "$CONTAINER_NAME"
    done
}

function create_network() {
  docker network rm integration_net 2> /dev/null
  docker network create --subnet=172.18.0.0/16 integration_net
  if [ "$HOST_NODE_PARENT_DIR" != "" ]; then
    # This code should only run in the subjenkins Docker container. It is necessary so that things running in
    # subjenkins (for example, the job that's running this script right now) can connect to things on the
    # integration_net network--in this case, to see whether or not they're running.
    docker network connect integration_net subjenkins
  fi
}

create_network

for PORT_LIST in $PORT_LISTS; do
    start_node "$CONTAINER_INDEX" "$PORT_LIST"
    START_RESULT=$?
    if [ "$START_RESULT" != "0" ]; then
        kill_containers_up_to "$CONTAINER_INDEX"
        exit 1
    fi
    ((CONTAINER_INDEX+=1))
done
