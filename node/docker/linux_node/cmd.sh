#!/bin/bash -xev

sudo cp /tmp/resolv.conf /etc/resolv.conf
sudo chmod -R 777 /node
export RUST_BACKTRACE=1
sudo /node/MASQNode --dns-servers 8.8.8.8 &
sudo dbus-daemon --system --fork
/usr/bin/firefox
