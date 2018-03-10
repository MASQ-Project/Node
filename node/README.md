# node
Probably the most interesting place to start

## Purpose
The purpose of `node` is to mask and un-mask CORES packages for clandestine routing.
It is also responsible for initializing all of the components of the SubstratumNode.

This is the project that generates the executable known as SubstratumNode.

## Tools / Environment Setup
SubstratumNode software is written in Rust.
We use `rustup` to install what we need (e.g. rustc, cargo, etc). Follow instructions [here](https://www.rustup.rs/).

The `node` project also uses `Docker` for a few things:
- **Running** SubstratumNode needs to be able to listen on port `53`, but Ubuntu 16.04 Desktop uses that port for
something else. So, we created the `Dockerfile` and helper scripts in `docker/linux_node/` to allow SubstratumNode 
to run on that platform. It isn't needed for running on Mac or Windows, or on Ubuntu 16.04 Server.
- **Testing** `Docker` also offered a convenient way for us to run our end-to-end integration tests for Mac and Linux on CI.
SubstratumNode needs to be started with `root` privileges in order to connect to certain ports (e.g. `53`, `80`).
The Jenkins agent that runs on Windows has the needed privileges by default, but the agents that run on Mac and Linux
do not. We created the `Dockerfile` in `docker/integration_tests` to work around this limitation.

This project depends on all of our library projects,
so you'll need to pull each of them into the same top-level directory as `node`:

- Workspace/
    - [substratum_sub_lib](https://github.com/SubstratumNetwork/substratum_sub_lib.git)/
    - [substratum_entry_dns_lib](https://github.com/SubstratumNetwork/substratum_entry_dns_lib.git)/
    - [substratum_hopper_lib](https://github.com/SubstratumNetwork/substratum_hopper_lib.git)/
    - [substratum_neighborhood_lib](https://github.com/SubstratumNetwork/substratum_neighborhood_lib.git)/
    - [substratum_proxy_client_lib](https://github.com/SubstratumNetwork/substratum_proxy_client_lib.git)/
    - [substratum_proxy_server_lib](https://github.com/SubstratumNetwork/substratum_proxy_server_lib.git)/
    - [substratum_node](https://github.com/SubstratumNetwork/substratum_proxy_server_lib.git)/

You'll also need an Internet connection when you build `node` so that `cargo` can pull down dependencies.

## How To
We build and run tests for `node` using bash scripts located in the `ci` directory.
Use `ci/all.sh` to clean, build, and run tests in one step.
It will run the integration tests as well, so if you're running on Mac or Linux make sure the `Docker` daemon is running.
_On Windows, we run these scripts in a git bash terminal._

### Run SubstratumNode locally

_Note: Currently, your DNS must be manually set to `127.0.0.1` in order to route traffic through SubstratumNode.
Find instructions for your platform [here](https://github.com/SubstratumNetwork/substratum_node/tree/master/docs/)._

Once you've successfully built the `node` executable and completed the manual setup steps,
you can run SubstratumNode locally from the command line:
```
<path to top-level workspace>/substratum_node/target/release/node --dns_servers 8.8.8.8
```
In the above example, we're using Google's DNS, `8.8.8.8`, but you can use your preferred DNS.
If you can't choose just one favorite DNS, you can also specify multiple, separated by a comma (`,`).

_Why do we send in `dns_servers`? SubstratumNodes still need to talk to the greater Internet.
See [the ProxyClient README](https://github.com/SubstratumNetwork/substratum_proxy_client_lib.git)
for more information._

# Disclosure

We run tests on every push to `master` on these platforms:
- Ubuntu 16.04 Desktop 64-bit
- MacOS High Sierra
- Windows 10 64-bit

SubstratumNode doesn't reliably build on 32-bit Windows due to issues with the build tools for that platform. We recommend using a 64-bit version to build.

We do plan to release binaries that will run on 32-bit Windows, but they will likely be built on 64-bit Windows.


Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
