#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

if [[ "$1" == "" ]]; then
  WORKSPACE="$HOME"
else
  WORKSPACE=$(echo "$1" | sed 's|\\|/|g; s|^\([A-Za-z]\):|/\1|g')
fi

echo "$WORKSPACE"
