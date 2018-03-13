#!/bin/bash -xev
# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

sudo cp /tmp/resolv.conf /etc/resolv.conf
sudo /node/node --dns_servers 8.8.8.8 &
sudo dbus-daemon --system --fork
/usr/bin/firefox
