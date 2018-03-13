#!/bin/bash
while read -r line; do
    process "$line"
done < <(cargo lichking check --all)