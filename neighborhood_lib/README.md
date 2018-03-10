# neighborhood_lib
Route generation for SubstratumNode

## Purpose
The purpose of `neighborhood_lib` is to generate Routes for CORES packages that originate from its own SubstratumNode.
It does this by cultivating a sparse map of other SubstratumNodes in the SubstratumNetwork.

It is built as a library, and is not intended as a standalone program.
It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/substratum_node.git) is a better place to start.

## Tools / Environment Setup
SubstratumNode software is written in Rust.
We use `rustup` to install what we need (e.g. rustc, cargo, etc). Follow instructions [here](https://www.rustup.rs/).

This project depends on the `sub_lib` project,
so you'll need to clone [sub_lib](https://github.com/SubstratumNetwork/substratum_sub_lib.git)
into the same top-level directory as `neighborhood_lib`:

- Workspace/
    - substratum_sub_lib/
    - substratum_neighborhood_lib/

You'll also need an Internet connection when you build `neighborhood_lib`, so that `cargo` can pull down dependencies.

## How To
We build and run tests for `neighborhood_lib` using bash scripts located in the `ci` directory.
Use `ci/all.sh` to clean, build, and run tests in one step.
_On Windows, we run these scripts in a git bash terminal._

In order to build and run the SubstratumNode software locally, you'll need to pull down
[sub_lib](https://github.com/SubstratumNetwork/substratum_sub_lib.git)
as well as our other supporting libraries,
[entry_dns_lib](https://github.com/SubstratumNetwork/substratum_entry_dns_lib.git),
[hopper_lib](https://github.com/SubstratumNetwork/substratum_hopper_lib.git),
[neighborhood_lib](https://github.com/SubstratumNetwork/substratum_neighborhood_lib.git),
[proxy_client_lib](https://github.com/SubstratumNetwork/substratum_proxy_client_lib.git),
[proxy_server_lib](https://github.com/SubstratumNetwork/substratum_proxy_server_lib.git),
and finally, the project that brings them all together,
[node](https://github.com/SubstratumNetwork/substratum_node.git).
Find detailed instructions in [node](https://github.com/SubstratumNetwork/substratum_node.git).

Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
