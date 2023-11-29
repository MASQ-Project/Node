# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

# linux/amd64
#FROM trufflesuite/ganache-cli:v6.7.0

# linux/arm64 (for MacOs VMs, in case the upper one did not work for you)
FROM --platform=linux/arm64 nutrina/ganache-cli:0.3

ADD ./entrypoint.sh /app/

EXPOSE 18545

ENTRYPOINT /app/entrypoint.sh
