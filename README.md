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

Once your DNS is successfully subverted, you can start the SubstratumNode itself.  Currently, there are two major ways
the SubstratumNode can run: zero-hop and decentralized.

A zero-hop SubstratumNode is very easy to start, and it's self-contained: every zero-hop SubstratumNode has an entire
Substratum Network inside it.  However, it doesn't communicate with any other SubstratumNodes.  Every network transaction
is zero-hop: your Node is the Client node, the Originating node, and the Exit node all at once.  A zero-hop SubstratumNode
is good for exploring the system and verifying its compatibility with your hardware, but it doesn't relay traffic through
any other Nodes.

A decentralized SubstratumNode is considerably more difficult to start, because you have to give it much more information
to get it running; however, it can route your traffic through other SubstratumNodes running elsewhere in the world to get
it to and from your destination.

__Important Note:__ Please remember that at the moment neither zero-hop Substratum Nodes nor decentralized SubstratumNodes
are secure or private in any sense of the word.  Please don't use them for any kind of sensitive traffic at this stage.

#### Running a Zero-Hop SubstratumNode locally

Here's all you need to start your zero-hop SubstratumNode:
```
$ sudo SubstratumNode/node/target/release/SubstratumNode --dns_servers 1.1.1.1
```
In the above example, we're using Cloudflare's DNS, `1.1.1.1`, but you can use your preferred DNS.
If you can't choose just one favorite DNS, you can also specify multiple ones, separated by a comma but no space (`,`).

_Why do we specify `--dns_servers`? SubstratumNodes still need to talk to the greater Internet.
See [the ProxyClient README](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/proxy_client_lib)
for more information._

#### Running a Decentralized SubstratumNode locally

There are several more options that are available for running decentralized. Here is a list of them and their meanings:

* `--ip <IP address>` This is the public IP address of your SubstratumNode: that is, the IP address at which other
SubstratumNodes can contact yours. If you're in a fairly standard residential situation, then this will be the IP
address issued to your router by your ISP, and in order to receive data you'll need to create holes in your router's
firewall to enable incoming data to reach you on your clandestine ports (see below).  In the future, this will be taken
care of for you (if you haven't turned off UPnP on your router), but right now it's manual.

* `--dns_servers <IP address>,...` This is the same list of DNS servers needed for zero-hop operation. Whenever your
SubstratumNode is used as an exit Node, it will contact these DNS servers to find the host the client is trying to reach.

* `--neighbor <public key>;<IP address>;<port>,<port>,...`
This is how you tell your Node about one of its neighbors. The `<public key>` is the Base64-encoded public key of the
neighbor in question. The `<IP address>` is the public IP address of that neighbor, and the `<port>` numbers are the
clandestine ports on which the neighbor is listening.  If this other Node is one you're running yourself, you'll see it
print this information to the console when it comes up.  If it's somewhere else on the Internet, you'll probably receive
this information in an email or chat message to copy/paste onto your command line.  You can specify as many `--neighbor`s
as you like.

* `--bootstrap_from <public key>;<IP address>;<port>,<port>,...`
This parameter has the same format as `--neighbor` above.  It tells your SubstratumNode where to find a bootstrap Node.
A bootstrap Node is a special kind of Node that does not route any data, but that holds information about the other
Nodes in the SubstratumNetwork. If you specify `--bootstrap_from`, you should not specify `--neighbor`, and vice versa.
(This is a temporary restriction that will be lifted in the future.)  Again, you can specify `--bootstrap_from` as many
times as you like.

* `--node_type < standard | bootstrap >`
This is how you tell SubstratumNode whether to start up as a bootstrap Node or as a standard (non-bootstrap) Node. If
you're interested in running data through the system, you won't find the `bootstrap` option particularly fulfilling, but
you should feel free to try it if you like.  Note: Bootstrap Nodes must start up with no knowledge of their environment,
so `--node_type bootstrap` will tolerate neither `--neighbor` nor `--bootstrap_from`.

* `--port_count <n>`
Specify the number of clandestine ports your SubstratumNode should listen on.  It will select the port numbers and
print them to the console when it starts up.  The default value of n is 0 (zero-hop).  Note: This is a temporary 
parameter; configuration like this will be done differently in the future.

* `--dns_target <IP address>`
The DNS server that is part of the SubstratumNode always gives the same answer to every query. This is how you can change
that answer: specify it here and the DNS server will direct all requests to the target you specify. The default, of
course, is `127.0.0.1`.  We found this parameter useful for testing, but we don't use it anymore and you probably won't
need it either.

* `--dns_port <port>`
Almost everything that uses a DNS server expects to find it listening on port 53.  In the early days of development,
we found it inconvenient to always put the DNS server on port 53, because it requires admin privilege to do so; so we
put in this parameter so that we could put it elsewhere and point tests at it.  Since then we've had to find ways to
do testing on low ports anyway, so now we always leave this parameter out and let it default to 53.  You probably won't
have much use for this.

* `--log_level < off | error | warn | info | debug | trace >`
The Node has the potential to log a lot of data. (A _lot_ of data: a busy Node can fill your disk in a few minutes.) This
parameter allows you to specify how much of that potential will be realized. `trace` will encourage the Node to reach its
full potential, and should probably only be used when you're going to run the Node for a few seconds to try one thing
that's been giving you problems, and then shut it off to look at the logs. `error` logs only the 
most serious of errors, and the other values are in-between compromise points. Default is `warn`.

If you try to start your SubstratumNode decentralized, you will quickly discover that these parameters have
a great deal of interdependence on each other.  Some are required, some are optional, some are optional only if others
are provided, and so on.  Here's a brief description of the dependencies.

In order to run decentralized, the SubstratumNode _must_ know the IP address others can use to contact it. Therefore,
you must supply `--ip`. You also must have some way of finding out about your network environment, so you must specify 
`--neighbor` or `--bootstrap_from` or `--node_type bootstrap`, but only one of those.  Also, your Node must have some
way to transfer clandestine traffic to and from other Nodes, so you must have a `--port_count` greater than zero.  
(1 is fine. 1000 is fine too, but you'll be poking holes in your router's firewall for awhile.)

Your home network is behind your internet provider's router and a public IP address. Other nodes in the Substratum Network
will communicate with your public IP address requiring some ports to be opened on your router. The Node gossip protocol 
"gossips" to other nodes the ports you are listening on and it is those ports you will need to open. When your node 
is started it will print the list of ports; you will need to forward those exact ports from your router to 
your computer's IP address.

Opening ports on your router is somewhat technical and at a minimum you should know how to login to your router in 
order to make changes. Opening a port is usually referred to as Port Forwarding or Port Mapping within a router's 
interface and maybe labeled as such. Assigning a Static IP for your computer will make this process easier as your 
IP address can change each time your computer restarts or you restart the network interface. There are many guides that 
you can find on the internet by searching for "Port Forwarding" or "How to Port Forwarding". 
Here is an example: [PortForward.com](https://portforward.com)

More information on the operation, care, and feeding of the Neighborhood is available
[in the neighborhood_lib subproject](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/neighborhood_lib).


### Terminating a SubstratumNode (Zero-Hop or Decentralized)

To terminate the SubstratumNode, just press Ctrl-C in the terminal window. Then you'll still need to revert your
machine's DNS settings:
```
$ sudo SubstratumNode/dns_utility/target/release/dns_utility revert
```
This should have you using the Internet normally again.

However, if you've been running decentralized, you'll probably want to close the holes in your router's firewall. Don't
leave them open against the next time you run: your Node will pick different clandestine ports the next time.

# Disclosure

We run tests on every push to `master` on these platforms:
- Ubuntu 16.04 Desktop 64-bit
- MacOS High Sierra
- Windows 10 64-bit

SubstratumNode doesn't reliably build on 32-bit Windows due to issues with the build tools for that platform. We 
recommend using a 64-bit version to build.

We do plan to release binaries that will run on 32-bit Windows, but they will likely be built on 64-bit Windows.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
