#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

"$CI_DIR/setup.sh"
"$CI_DIR/link_binaries.sh"

case "$OSTYPE" in
   linux*)
        yarn dist --x64 --linux deb
        ;;
   darwin*)
        yarn dist --x64 --mac
        ;;
   msys)
        yarn dist --x64 --windows
        ;;
   *)
        echo "unsupported operating system detected."; exit 1
        ;;
esac

