#!/bin/sh
# substratum node privilege dropper sudo hack, because electron-sudo fakes sudo on linux
export SUDO_UID=$1
export SUDO_GID=$2
shift 2
echo PID=$$
$@ > /dev/null # ignore stdout to avoid overflowing the buffer


