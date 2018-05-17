# SubstratumNode

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
We use `rustup` to install what we need (e.g. `rustc`, `cargo`, etc). If you don't already have it, you can get it from
[the `rustup` installation page](https://www.rustup.rs/).

Some Linux distributions (notably Ubuntu ≥16.04 Desktop) have an incompatibility with SubstratumNode. If you think
you might be affected, see 
[The Port 53 Problem](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node/docs/PORT_53.md) 
for more information.

If you're using Windows, you'll need to run the build scripts using `git-bash`. If you've cloned this repository, you
probably already have `git-bash`; but if you don't, look at
[How To Install `git-bash` On Windows](http://www.techoism.com/how-to-install-git-bash-on-windows/).

Also, you will need an Internet connection when you build so that `cargo` can pull down dependencies.

## How To
We build and run tests for SubstratumNode using `bash` scripts located in the `ci` directory of each sub-project.
To clean, build, and run tests for all sub-projects in one step, start at the top level of the project (the directory
is probably called `SubstratumNode`).

#### If you're using Linux or macOS 
First, please note that at a few points during the process, the build will stop and ask you for your password. This is 
because some of the integration tests need to run with root privilege, to change DNS settings, open low-numbered ports, 
etc. (It is possible but not easy to build without giving root privilege or running integration tests; if this turns
out to be something people want to do, we'll make it easier.)

Open a standard terminal window and type:
```
$ ci/all.sh
```

#### If you're using Windows
Open a `git-bash` window as administrator and type:
```
$ ci/all.sh
```

_Wondering where all our tests are? The convention in Rust is to write unit tests in same file as the source, in a module
at the end._

### Run SubstratumNode locally

Once you've successfully built the `node` executable, you can run SubstratumNode from the command line.

Currently, your DNS must be set to `127.0.0.1` in order to route traffic through SubstratumNode; then it must be set back to
whatever it was before when you're done with SubstratumNode and you want to get back on the normal Internet.


The SubstratumNode software includes a 
[multi-platform DNS utility](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/dns_utility) that you can use
to subvert your DNS settings to `127.0.0.1`, like this:
```
$ cd <path to workspace>
$ sudo SubstratumNode/dns_utility/target/release/dns_utility subvert
```
If you have trouble with `dns_utility` or you'd rather make your DNS configuration changes manually, look for 
[instructions for your platform](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node/docs).

Once your DNS is successfully subverted, you can start the SubstratumNode itself:
```
$ sudo SubstratumNode/node/target/release/SubstratumNode --dns_servers 1.1.1.1
```
In the above example, we're using Cloudflare's DNS, `1.1.1.1`, but you can use your preferred DNS.
If you can't choose just one favorite DNS, you can also specify multiple ones, separated by a comma (`,`).

_Why do we specify `--dns_servers`? SubstratumNodes still need to talk to the greater Internet.
See [the ProxyClient README](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/proxy_client_lib)
for more information._

To terminate the SubstratumNode, just press Ctrl-C in the terminal window. Then you'll still need to revert your
machine's DNS settings:
```
$ sudo SubstratumNode/dns_utility/target/release/dns_utility revert
```
This should have you using the Internet normally again.

# Disclosure

We run tests on every push to `master` on these platforms:
- Ubuntu 16.04 Desktop 64-bit
- MacOS High Sierra
- Windows 10 64-bit

SubstratumNode doesn't reliably build on 32-bit Windows due to issues with the build tools for that platform. We recommend using a 64-bit version to build.

We do plan to release binaries that will run on 32-bit Windows, but they will likely be built on 64-bit Windows.


Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
