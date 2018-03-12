# substratum_node_plex

## Purpose
FIXME add marketing language about the overall product "SubstratumNode"

## Tools / Environment Setup
SubstratumNode software is written in Rust.
We use `rustup` to install what we need (e.g. rustc, cargo, etc). Follow instructions [here](https://www.rustup.rs/).

The `node` sub-project also uses `Docker` for a few things:
- **Running** SubstratumNode needs to be able to listen on port `53`, but Ubuntu 16.04 Desktop uses that port for
something else. So, we created the `Dockerfile` and helper scripts in `docker/linux_node/` to allow SubstratumNode 
to run on that platform. It isn't needed for running on Mac or Windows, or on Ubuntu 16.04 Server.
- **Testing** `Docker` also offered a convenient way for us to run our end-to-end integration tests for Mac and Linux on CI.
SubstratumNode needs to be started with `root` privileges in order to connect to certain ports (e.g. `53`, `80`).
The Jenkins agent that runs on Windows has the needed privileges by default, but the agents that run on Mac and Linux
do not. We created the `Dockerfile` in `docker/integration_tests` to work around this limitation.

This project is made up of several sub-projects:

- substratum_node_plex/
    - [sub_lib](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/sub_lib)/
    - [entry_dns_lib](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/entry_dns_lib)/
    - [hopper_lib](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/hopper_lib)/
    - [neighborhood_lib](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/neighborhood)/
    - [proxy_client_lib](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/proxy_client_lib)/
    - [proxy_server_lib](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/proxy_server_lib)/
    - [node](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/node)/

You'll need an Internet connection when you build so that `cargo` can pull down dependencies.

## How To
We build and run tests for SubstratumNode using bash scripts located in the `ci` directory of each sub-project.
Use `ci/all.sh` at the top level to clean, build, and run tests for all sub-projects in one step.
It will run the `node` integration tests as well, so if you're running on Mac or Linux make sure the `Docker` daemon is running.
_On Windows, we run this script in a git bash terminal._

### Run SubstratumNode locally

_Note: Currently, your DNS must be manually set to `127.0.0.1` in order to route traffic through SubstratumNode.
Find instructions for your platform [here](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/node/docs)._

Once you've successfully built the `node` executable and completed the manual setup steps,
you can run SubstratumNode locally from the command line:
```
<path to workspace>/substratum_node_plex/node/target/release/node --dns_servers 8.8.8.8
```
In the above example, we're using Google's DNS, `8.8.8.8`, but you can use your preferred DNS.
If you can't choose just one favorite DNS, you can also specify multiple, separated by a comma (`,`).

_Why do we send in `dns_servers`? SubstratumNodes still need to talk to the greater Internet.
See [the ProxyClient README](https://github.com/SubstratumNetwork/substratum_node_plex/tree/master/proxy_client_lib)
for more information._

# Disclosure

We run tests on every push to `master` on these platforms:
- Ubuntu 16.04 Desktop 64-bit
- MacOS High Sierra
- Windows 10 64-bit

SubstratumNode doesn't reliably build on 32-bit Windows due to issues with the build tools for that platform. We recommend using a 64-bit version to build.

We do plan to release binaries that will run on 32-bit Windows, but they will likely be built on 64-bit Windows.


Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
