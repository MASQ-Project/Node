# substratum_node

## Purpose
SubstratumNetwork is an open-source network that allows anyone to allocate spare computing resources to make the internet
a free and fair place for the entire world. It is a worldwide collection of nodes that securely delivers content without
the need of a VPN or Tor.

Because there's no single authority delivering or monitoring content, censorship and geo-restricted sites won't be an
issue on SubstratumNetwork. It doesn't matter where you live or what content you're accessing, everyone in the world
sees the exact same content.

**SubstratumNode** is the foundation of SubstratumNetwork.

It is what the average user runs to earn SUB and dedicate some of their computers' resources towards the network.
People who run a SubstratumNode can be rewarded with cryptocurrency for each time they serve content.

SubstratumNodes work together to relay CORES packages and content on the network.
When a user requests a site, nodes use artificial intelligence to find the most expedient and secure way to get the
information to that user. Multiple nodes work to fulfill a single request in order to maintain a necessary level of anonymity.

## Tools / Environment Setup
SubstratumNode software is written in Rust.
We use `rustup` to install what we need (e.g. rustc, cargo, etc). Follow instructions [here](https://www.rustup.rs/).

The `node` sub-project also uses `Docker` for a few things:
- **Running** SubstratumNode needs to be able to listen on port `53`, but Ubuntu 16.04 Desktop uses that port for
something else. So, we created the `Dockerfile` and helper scripts in `substratum_node/node/docker/linux_node/` to
allow SubstratumNode to run on that platform. It isn't needed for running on Mac or Windows, or on Ubuntu 16.04 Server.
- **Testing** `Docker` also offered a convenient way for us to run our end-to-end integration tests for Mac and Linux on CI.
SubstratumNode needs to be started with `root` privileges in order to connect to certain ports (e.g. `53`, `80`).
The Jenkins agent that runs on Windows has the needed privileges by default, but the agents that run on Mac and Linux
do not. We created the `Dockerfile` in `substratum_node/node/docker/integration_tests` to work around this limitation.

You'll need an Internet connection when you build so that `cargo` can pull down dependencies.

## How To
We build and run tests for SubstratumNode using bash scripts located in the `ci` directory of each sub-project.
Use `ci/all.sh` at the top level to clean, build, and run tests for all sub-projects in one step.
It will run the `node` integration tests as well, so if you're running on Mac or Linux make sure the `Docker` daemon is running.
_On Windows, we run this script in a git bash terminal._

_Wondering where all our tests are? The convention in Rust is to write unit tests in same file as the source._

### Run SubstratumNode locally

_Note: Currently, your DNS must be manually set to `127.0.0.1` in order to route traffic through SubstratumNode.
Find instructions for your platform [here](https://github.com/SubstratumNetwork/substratum_node/tree/master/node/docs)._

Once you've successfully built the `node` executable and completed the manual setup steps,
you can run SubstratumNode locally from the command line:
```
<path to workspace>/substratum_node/node/target/release/node --dns_servers 8.8.8.8
```
In the above example, we're using Google's DNS, `8.8.8.8`, but you can use your preferred DNS.
If you can't choose just one favorite DNS, you can also specify multiple, separated by a comma (`,`).

_Why do we send in `dns_servers`? SubstratumNodes still need to talk to the greater Internet.
See [the ProxyClient README](https://github.com/SubstratumNetwork/substratum_node/tree/master/proxy_client_lib)
for more information._

# Disclosure

We run tests on every push to `master` on these platforms:
- Ubuntu 16.04 Desktop 64-bit
- MacOS High Sierra
- Windows 10 64-bit

SubstratumNode doesn't reliably build on 32-bit Windows due to issues with the build tools for that platform. We recommend using a 64-bit version to build.

We do plan to release binaries that will run on 32-bit Windows, but they will likely be built on 64-bit Windows.


Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
