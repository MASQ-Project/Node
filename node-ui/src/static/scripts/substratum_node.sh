#!/bin/sh
# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
# substratum node privilege dropper sudo hack, because electron-sudo fakes sudo on linux
export SUDO_UID=$1
export SUDO_GID=$2
shift 2
echo PID=$$

$@ > /dev/null # ignore stdout to avoid overflowing the buffer

# Uncomment these to get println!s from Node logged to a file
#touch /tmp/node_log.txt
#chmod 777 /tmp/node_log.txt
#$@ >> /tmp/node_log.txt
