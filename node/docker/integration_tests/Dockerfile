# Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
FROM rust:1.23.0

ENV SUDO_UID=1000
ENV SUDO_GID=1000

WORKDIR /node_root/node
CMD ["bash", "-c", "$(pwd)/ci/run_integration_tests.sh"]
