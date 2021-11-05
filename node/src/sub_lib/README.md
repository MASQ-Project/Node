# `sub_lib`
Common code for MASQ Rust projects

## Purpose
The purpose of `sub_lib` is to hold the common code for all the shared submodules we use in the `node` subproject.

It is built as a library, and is not intended as a standalone program.

Historically, each different submodule of `node` was its own separate project, and `sub_lib`
(`sub` for Substratum) was the project that held all the common code. Later, the projects
(including `sub_lib`) were all combined into the `node` project. After that, the need for
separate projects (like `masq` and `dns_utility` and `multinode_integration_tests`) reasserted
itself on a different level, and we needed another place to put common code. Since by that time
our name was MASQ instead of Substratum, all that code went into the `masq_lib` project.

We think it's unlikely that the current projects in the MASQNode repository will ever be
consolidated into one, so both `sub_lib` and `masq_lib` will probably continue to exist at
their separate levels, although at some point they may take on more descriptive names.

This probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/MASQ-Project/Node/tree/master/node)
is a better place to start.

Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
