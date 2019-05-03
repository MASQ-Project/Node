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

To keep our source code consistently formatted, we use `rustfmt`, which is a plugin for `cargo`. If you want to use our
build scripts to build the code, you'll need to [install this plugin in your Rust environment](https://github.com/rust-lang/rustfmt).
(We use the stable version, not the nightly version.)

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
Substratum Node utilizes a Web3 crate to facilitate Blockchain communications. The Web3 crate depends on OpenSSL for TLS
when connecting over HTTPS. Some setup for a proper Windows build environment may be needed. You have two choices: a) install
OpenSSL and allow it to be dynamically linked at compile time b) download an OpenSSL binary and set `OPENSSL_STATIC`
and allow it to be statically linked at compile time.
See the [Rust OpenSSL Documentation](https://docs.rs/openssl/0.10.20/openssl/) for more information on configuring this 
environment variable. If it is not set, dynamic linking is assumed. The binaries we distribute are statically linked.

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
See [the ProxyClient README](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node/src/proxy_client)
for more information._

#### Running a Decentralized SubstratumNode locally

There are several more options that are available for running decentralized. Here is a list of them and their meanings:

* `--blockchain_service_url <url>` An optional URL that should point to an Infura, Geth, or Parity HTTP endpoint. Not 
supplying a URL will direct blockchain traffic through the Substratum Network, allowing those nodes that do supply the 
URL to talk to the blockchain on your behalf.

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
this information in an email or chat message to copy/paste onto your command line.  You can specify as many `--neighbor`
parameters as you like.

* `--node_type < standard | bootstrap >`
This is how you tell SubstratumNode whether to start up as a bootstrap-only Node or as a standard (non-bootstrap) Node. If
you're interested in running data through the system, you won't find the `bootstrap` option particularly fulfilling, but
you should feel free to try it if you like.  Note: Bootstrap-only Nodes must start up with no knowledge of their environment,
so `--node_type bootstrap` will not tolerate `--neighbor`.

* `--port_count <n>`
Specify the number of clandestine ports your SubstratumNode should listen on.  It will select the port numbers and
print them to the console when it starts up.  The default value of n is 0 (zero-hop).  Note: This is a temporary 
parameter; configuration like this will be done differently in the future.

* `--log_level < off | error | warn | info | debug | trace >`
The Node has the potential to log a lot of data. (A _lot_ of data: a busy Node can fill your disk in a few minutes.) This
parameter allows you to specify how much of that potential will be realized. `trace` will encourage the Node to reach its
full potential, and should probably only be used when you're going to run the Node for a few seconds to try one thing
that's been giving you problems, and then shut it off to look at the logs. `error` logs only the 
most serious of errors, and the other values are in-between compromise points. Default is `warn`.

* `--ui_port <port>`
This is how you tell the node which port it should listen on for local WebSocket connections to the UI gateway. This allows
the node to be controlled and inspected by other programs, such as the Substratum Node UI. The default port is 5333; in most
cases, this will not need to be changed.

* `--data_directory <directory>`
This is the directory in which Node will keep the state that needs to persist from run to run. If it's not specified, the
default is `$XDG_DATA_HOME` or `$HOME/.local/share` on Linux, `{FOLDERID_RoamingAppData}` on Windows, and 
`$HOME/Library/Application Support` on MacOS. If it is specified but doesn't exist, Node will try to create the directory
and abort if it fails. If persistent state exists in the directory, but it was created by a version of Node that is
incompatible with the version you're trying to start, Node will abort. If this is the case, either remove the existing
state and restart Node, or specify a different `--data_directory` directory.

If you try to start your SubstratumNode decentralized, you will quickly discover that these parameters have
a great deal of interdependence on each other.  Some are required, some are optional, some are optional only if others
are provided, and so on.  Here's a brief description of the dependencies.

In order to run decentralized, the SubstratumNode _must_ know the IP address others can use to contact it. Therefore,
you must supply `--ip`. You also must have some way of finding out about your network environment, so you must specify 
`--neighbor` or `--node_type bootstrap`, but only one of those.  Also, your Node must have some
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
[in the neighborhood_subproject](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node/src/neighborhood).


### Terminating a SubstratumNode (Zero-Hop or Decentralized)

To terminate the SubstratumNode, just press Ctrl-C in the terminal window. Then you'll still need to revert your
machine's DNS settings:
```
$ sudo SubstratumNode/dns_utility/target/release/dns_utility revert
```
This should have you using the Internet normally again.

However, if you've been running decentralized, you'll probably want to close the holes in your router's firewall. Don't
leave them open against the next time you run: your Node will pick different clandestine ports the next time.

## Errors

SubstratumNode, like any other piece of software, can encounter obstacles it cannot overcome in the process of trying
to do what you ask it to do.  It needs to be able to tell you about these insurmountable obstacles, but it lives in a
place that makes this difficult.  If it were a Web browser, it would have a window on which to display error messages.
If it were a Web server it could send data describing the errors to your browser to display. But it's neither of these
things; instead, it's crowded into a place in the protocol stack where neither the browser nor the server expects it
to exist.

Therefore, certain error messages are a bit awkward to display, especially if they involve TLS connections. Let's look
at how SubstratumNode deals with certain kinds of errors.

### HTTP

An insecure HTTP connection is one that is based on a URL that begins with `http://` (as opposed to `https://`). The
fact that it is insecure means that SubstratumNode (and every other process that handles the data) can intrude on the
data stream and make your browser display whatever they want it to, which may or may not be related to what the server
on the other end of the connection intended.

When errors occur, this is very useful for SubstratumNode. If you request something from an HTTP server, and for some
reason SubstratumNode cannot relay your request to that server, or cannot relay the response from the server back to
you, it will instead impersonate the server and create a counterfeit response describing the error, and display that
to you instead of the server response it can't give you. (Don't worry: SubstratumNode's impersonation of the server
is deliberately very bad, so you can easily tell that the error is not coming from the server. You won't be misled).
The error message will describe the problem and suggest ways it might be alleviated.

### TLS

TLS (spoken over connections based on URLs that begin with `https://`) is a much more difficult beast. Once a TLS 
connection is set up between your browser and a server, SubstratumNode cannot understand a single bit of the dataflow,
and it cannot modify a single bit of it without your browser throwing red alerts and refusing to show you the modified
data. This is good for you and your privacy, but it doesn't make it easy for SubstratumNode to communicate with you
via the browser.

There is a small exception.

_Once a TLS connection is set up,_ it's completely secure. But _while_ it's being set up, before the encrypted tunnel has
been established, there's a little SubstratumNode can do. Specifically, it can inject what's called a TLS Alert into the
stream of data, as long as it is injected very early. This TLS Alert has a single byte that SubstratumNode can use to tell
you about problems it has relaying your data. There are a number of predefined values this byte can take on, and
SubstratumNode has to pick one of these values: it can't make up its own.

If your browser is trying to load a page when the error occurs, you'll see a cryptic message in its window telling you
that you're not going to get what you're after. The exact wording of the error depends on the exact type of the TLS
Alert. If your browser is trying to communicate in the background when the error occurs, you probably won't see it on
the screen; but if the browser stops responding, you can open its developer tools and check the JavaScript console; if
SubstratumNode sent a TLS Alert, you'll see it there.

Since the concerns of the SubstratumNode aren't precisely the same as the concerns of a TLS endpoint, the correspondence
can't always be made exact, so here are some specific TLS Alert values that SubstratumNode produces in specific 
situations.

* Routing Failure - `internal_error`: If your Node is not yet "warmed up" enough in the Substratum Network to see a
large enough neighborhood to be able to create a clandestine route that meets your specifications, it will raise a
TLS `internal_error` Alert. This will probably be displayed by your browser as some sort of protocol error--which,
strictly speaking, it is. If this happens, just wait awhile for your Node and the Substratum Network to Gossip with
each other and spread around the necessary information. Then try reloading the page.

* DNS Resolution Failure - `unrecognized_name`: Even though you contact websites at names like `google.com` and
`facebook.com`, the real Internet operates on the basis of IP addresses (like `172.217.6.14` and `31.13.66.35`).
Before it's useful for retrieving data, your server name has to be translated into an IP address. This is the job of a
DNS server. Much of Internet censorship consists of crippling the DNS servers you have available to you so that they
can't give you the correct IP address for the server name you're seeking. SubstratumNode captures the DNS queries your
browser makes and forwards them across the Substratum Network to some other Node that hopefully has access to a
non-censored DNS server that _does_ know the IP address you want. But this is a complex task and it may fail. For
example, perhaps you typed the server name wrong, and _nobody_ knows an IP address it matches. Or perhaps your
SubstratumNode guessed wrong, and the exit Node to which it forwarded your DNS query is also handicapped by a censored DNS
and can't find it either. In either case, SubstratumNode will send your browser a TLS `unrecognized_name` alert, which
your browser will probably present to you as some form of can't-find-host error. If you reload the page, SubstratumNode
will try to select a different exit Node, if available--one that hasn't failed to resolve a DNS query--for the next 
attempt, which might bring you better fortune. Of course, if you _have_ typed the name wrong, just reloading the page
will take another innocent exit Node out of circulation and make it even harder for you to get where you want to go.

# Disclosure

We run tests on every push to `master` on these platforms:
- Ubuntu 16.04 Desktop 64-bit
- MacOS High Sierra
- Windows 10 64-bit

SubstratumNode doesn't reliably build on 32-bit Windows due to issues with the build tools for that platform. We 
recommend using a 64-bit version to build.

We do plan to release binaries that will run on 32-bit Windows, but they will likely be built on 64-bit Windows.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
