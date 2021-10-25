# These Tests Must Be Serialized

Since these tests create, use, and destroy the Docker `integration_net` network,
they must run one at a time, rather than in parallel.  Cargo wants to run them
in parallel, and must be specifically ordered not to do so.

`ci/all.sh` is designed to give Cargo the proper serialization orders, but
IntelliJ is not. If you run these tests from IntelliJ, make sure to run only
one at a time. If you want to run several, use `ci/all.sh` or a specific 
`cargo` command that works like `ci/all.sh` does.

Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
