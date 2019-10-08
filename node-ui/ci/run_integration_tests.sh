#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/../main-process"
umask 0000
yarn spec
[[ -n "$SUDO_UID" ]] && [[ -n "$SUDO_GID" ]] && chown -R $SUDO_UID:$SUDO_GID *
popd
