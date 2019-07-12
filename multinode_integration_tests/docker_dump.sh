#!/bin/bash -xve

OUTPUT_DIR="$1"
mkdir -p "$OUTPUT_DIR"
for container in $(docker ps -a | tail -n +2 | cut -c 128- | grep test_node_)
do
    ./docker_logs.sh "$container" > "$OUTPUT_DIR"/"$container".log
done
