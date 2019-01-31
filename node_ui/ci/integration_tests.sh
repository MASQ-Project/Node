#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

NODE_BINARY="$(which node)"
NODE_DIR="$(dirname "$NODE_BINARY")"

function start_not_windows {
    SUDO_UID=$UID
    SUDO_GID=$(id -g)
    sudo -E PATH="$PATH:$NODE_DIR" SUDO_UID=$SUDO_UID SUDO_GID=$SUDO_GID "$CI_DIR/run_integration_tests.sh"
}

"$CI_DIR/link_binaries.sh"

case "$OSTYPE" in
    msys)
        echo "Windows"
        "$CI_DIR/run_integration_tests.sh"
        ;;
    Darwin | darwin*)
        echo "macOS"
        start_not_windows
        ;;
    linux-gnu)
        echo "Linux"
        start_not_windows
        ;;
    *)
        exit 1
        ;;
esac
