#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

CI_DIR="$( cd "$( dirname "$0" )" && pwd )"
TOOLCHAIN_HOME="$1"

pushd "$CI_DIR/.."
case "$OSTYPE" in
    msys)
        echo "Windows"
        [[ $GITHUB_ACTIONS -eq true ]] && net stop sharedaccess || echo ICS already disabled
        [[ $GITHUB_ACTIONS -eq true ]] && net stop W3SVC || echo W3SVC service already disabled
        ci/run_integration_tests.sh
        ;;
    Darwin | darwin*)
        echo "macOS"
        [[ $GITHUB_ACTIONS -eq true ]] && sudo launchctl limit maxfiles 524288 524288 && ulimit -Sn 524288 && sudo launchctl limit maxfiles
        sudo --preserve-env ci/run_integration_tests.sh "$TOOLCHAIN_HOME"
        ;;
    linux-gnu)
        echo "Linux"
        [[ $GITHUB_ACTIONS -eq true ]] && sudo --preserve-env ci/free-port-53.sh
        sudo --preserve-env ci/run_integration_tests.sh "$TOOLCHAIN_HOME"
        ;;
    *)
        exit 1
        ;;
esac
popd
