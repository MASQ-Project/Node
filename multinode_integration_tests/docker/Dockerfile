# Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
FROM debian:buster-slim

RUN apt-get update && \
    apt-get install -y libc6 && \
    apt-get install -y iptables-persistent
COPY generated/port_exposer /usr/local/bin/port_exposer

ENV SUDO_UID 1000
ENV SUDO_GID 1000

CMD tail -f /dev/null
