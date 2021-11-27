# Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
FROM rust:1.23.0

ENV SUDO_UID=1000
ENV SUDO_GID=1000

WORKDIR /node_root/node
CMD ["bash", "-c", "$(pwd)/ci/run_integration_tests.sh"]
