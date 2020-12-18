#!/bin/bash
systemctl disable systemd-resolved.service
service systemd-resolved stop
# [[ -e /etc/resolv.conf ]] && cat /etc/resolv.conf
[[ -e /etc/resolv.conf ]] && sed -i 's/127.0.0.53/1.1.1.1/g' /etc/resolv.conf
