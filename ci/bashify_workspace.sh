#!/bin/bash -xev
# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

if [[ "$1" == "" ]]; then
  WORKSPACE="$HOME"
else
  WORKSPACE=$(echo "$1" | sed 's|\\|/|g; s|^\([A-Za-z]\):|/\1|g')
fi

echo "$WORKSPACE"
