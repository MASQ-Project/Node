#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

# TODO: fix packaging up binaries; currently the binary is not being packaged up
case "$OSTYPE" in
   linux*)
        yarn dist --x64 --linux deb
        ;;
   darwin*)
        yarn dist --x64 --mac
        ;;
   mssys)
        yarn dist --x64 --windows
        ;;
   *)
        echo "unsupported operating system detected."; exit 1
        ;;
esac

