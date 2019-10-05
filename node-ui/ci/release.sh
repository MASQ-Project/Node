#!/bin/bash -xev
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "$CI_DIR/.."
ci/setup.sh
ci/build.sh
ci/copy_binaries.sh

pushd "main-process"
case "$OSTYPE" in
   linux*)
        yarn dist --x64 --linux deb --publish=never
        ;;
   darwin*)
        yarn dist --x64 --mac --publish=never
        ;;
   msys)
        yarn dist --x64 --windows --publish=never
        ;;
   *)
        echo "unsupported operating system detected."; exit 1
        ;;
esac
popd
popd
