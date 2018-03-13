#!/bin/bash
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
while read -r line; do
    process "$line"
done < <(cargo lichking check --all)