#!/bin/bash -e
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
echo "Checking licenses referenced in Cargo.toml dependencies..."
shopt -s nocasematch
license_errors=$(date +"./%Y-%m-%d-%H%M-license-errors.tmp")
while read -r line; do
    if [[ ! $line =~ warning..ianal.* ]]; then
        if [[ $line =~ error.* ]]; then
            echo $line >> $license_errors
        elif [[ $line =~ warning.* ]]; then
            echo $line >> $license_errors
        fi
    fi
done < <(cargo lichking check --all 2>&1)

if [[ -s $license_errors ]]; then
  cat $license_errors
  rm $license_errors
  exit 1
fi
echo "License check successful!"
