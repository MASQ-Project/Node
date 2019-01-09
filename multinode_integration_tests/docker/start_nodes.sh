#!/bin/bash -xv
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

DOCKER_DIR="$( cd "$( dirname "$0" )" && pwd )"

PORT_LISTS=""
STARTUP_RETRY_MAX=5
CONTAINER_INDEX=1
KNOWN_NEIGHBORS=""

function parse_command_line() {
    while [[ $# -gt 0 ]]
    do
    key="$1"

    case $key in
        -n|--neighbor)
        KNOWN_NEIGHBORS="$KNOWN_NEIGHBORS --neighbor $2"
        shift # past argument
        shift # past value
        ;;
        *)    # unknown option
        PORT_LISTS="$PORT_LISTS $1" # save it in an array for later
        shift # past argument
        ;;
    esac
    done
}

parse_command_line $@

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
        sleep 0.5
    done
}

function start_node() {
    local INDEX="$1"
    local PORT_LIST="$2"
    local CONTAINER_IP="172.18.1.$INDEX"
    local CONTAINER_NAME="test_node_$INDEX"
    echo "Initiating start of $CONTAINER_NAME on $CONTAINER_IP"
    local COMMAND="/node_root/node/SubstratumNode"
    # TODO: Trash IP used here to make the test pass; fix this
    local ARGS="--dns_servers 1.1.1.1 --ip $CONTAINER_IP --neighbor R29vZEtleQ:1.2.3.4:1234,2345,3456 --port_count 1 --log_level trace $KNOWN_NEIGHBORS"
    local DOCKER_RUN="docker run --detach --ip $CONTAINER_IP --dns 127.0.0.1 --rm --name $CONTAINER_NAME --net integration_net -v $COMMAND_DIR:/node_root/node test_node_image $COMMAND $ARGS"
    echo "$DOCKER_RUN"
    $DOCKER_RUN
    local RUN_RESULT=$?
    if [ "$RUN_RESULT" != "0" ]; then
        echo "docker run failed: $RUN_RESULT"
        return 1
    fi
    wait_for_startup "$CONTAINER_IP"
    update_known_neighbors "$CONTAINER_NAME" "$CONTAINER_IP" "$PORT_LIST"
}

function update_known_neighbors() {
    local NEIGHBOR_NAME="$1"
    local NEIGHBOR_IP="$2"
    local NEIGHBOR_PORT_LIST="$3" # Temporary
    local NEIGHBOR_KEY="$(docker logs "$NEIGHBOR_NAME" | head -n 2 | tail -n 1 | cut -f5 -d' ')"
    local NEIGHBOR_PARAM="--neighbor $NEIGHBOR_KEY:$NEIGHBOR_IP:$NEIGHBOR_PORT_LIST"
    KNOWN_NEIGHBORS="$KNOWN_NEIGHBORS $NEIGHBOR_PARAM"
}

function kill_containers_up_to() {
    local LIMIT="$1"
    for INDEX in $(seq 1 "$LIMIT"); do
        CONTAINER_NAME="test_node_$INDEX"
        echo "Attempting to kill container $CONTAINER_NAME"
        docker stop -t 0 "$CONTAINER_NAME"
    done
}

function stop_running_nodes() {
    docker ps -a -q --filter ancestor="test_node_image" | xargs docker stop -t 0
}

function create_network() {
  docker network disconnect integration_net subjenkins # just in case we're in Jenkins; ignore error if not
  docker network rm integration_net
  docker network create --subnet=172.18.0.0/16 integration_net
  if [ "$HOST_NODE_PARENT_DIR" != "" ]; then
    # This code should only run in the subjenkins Docker container. It is necessary so that things running in
    # subjenkins (for example, the job that's running this script right now) can connect to things on the
    # integration_net network--in this case, to see whether or not they're running.
    docker network connect integration_net subjenkins
  fi
}

stop_running_nodes
create_network

for PORT_LIST in $PORT_LISTS; do
    start_node "$CONTAINER_INDEX" "$PORT_LIST"
    START_RESULT=$?
    if [ "$START_RESULT" != "0" ]; then
        echo "Starting container $CONTAINER_INDEX failed."
        kill_containers_up_to "$CONTAINER_INDEX"
        exit 1
    fi
    ((CONTAINER_INDEX+=1))
done
exit 0
