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
SubstratumNode utilizes a Web3 crate to facilitate Blockchain communications. The Web3 crate depends on OpenSSL for TLS
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
is zero-hop: your SubstratumNode is the Client node, the Originating node, and the Exit node all at once.  A zero-hop SubstratumNode
is good for exploring the system and verifying its compatibility with your hardware, but it doesn't relay traffic through
any other SubstratumNodes.

A decentralized SubstratumNode is considerably more difficult to start, because you have to give it much more information
to get it running; however, it can route your traffic through other SubstratumNodes running elsewhere in the world to get
it to and from your destination.

__Important Note:__ Please remember that at the moment neither zero-hop SubstratumNodes nor decentralized SubstratumNodes
are secure or private in any sense of the word.  Please don't use them for any kind of sensitive traffic at this stage.

#### Supplying Configuration To SubstratumNode

There are three ways to get configuration information into a SubstratumNode on startup. In decreasing level of priority,
these are:

1. the command line
2. the shell environment
3. the configuration file

Any piece of configuration information can be provided through any of these channels, with one exception: the path to
the configuration file cannot be taken from the configuration file. (It can be provided there, but it will never be
taken from there.) Configuration information provided in the environment will supersede conflicting information
provided in the configuration file, and information provided on the command line will supersede conflicting information
from both of the other sources.

##### Command line

This is the easiest. In this file, all our documentation of the configuration options shows you how to provide them on
the command line. Keep in mind, though, that command lines tend to be preserved by the operating system for display to
users who want to see process lists. Therefore, the command line may not be the best place to specify sensitive or
secret configuration information. (Nothing prevents you from doing this, though, so be careful.)

##### Shell Environment

If you see that the command line accepts a parameter such as `--clandestine-port 1234`, then you can supply that same
parameter in the environment by setting the `SUB_CLANDESTINE_PORT` environment variable to `1234`. Note that you need
to remove the initial `--` prefix, convert the name to all uppercase, and add a `SUB_` prefix to namespace the parameter
against other applications that might look for a similar variable.

##### Configuration File

The configuration file, by default, resides in the data directory (see the `--data-directory` parameter for further
information) and is named `config.toml`. If you leave the configuration file unspecified, this is where SubstratumNode
will look for it. If it's found, it will be used; if it's not, SubstratumNode will act as though it had been found but empty.
But if you want to use a different file, specify it either as `--config-file` on the command line or as `SUB_CONFIG_FILE`
in the environment. If you specify a relative filename, SubstratumNode will look for the configuration file in the data
directory; if you specify an absolute filename, SubstratumNode will not use the data directory to find the configuration
file.

The configuration file should be in TOML format. TOML is a competitor to other formats like JSON and YAML, but the
SubstratumNode uses only scalar settings, not arrays or tables. If you see that the command line accepts a parameter such
as `--clandestine-port 1234`, then you can supply that same parameter in the configuration file by adding the following
line to it:

```
clandestine-port = "1234"
```

Note that you need to remove the initial `--` prefix. All the configuration parameters will work if you supply their
values as double-quoted strings, but if they're numeric values, you can supply them numerically as well--for example,

```
clandestine-port = 1234
```

Keep in mind that a configuration file is persistent information: anyone who has or can gain read access to the file
can read whatever's in it, whether SubstratumNode is running or not. Therefore, the configuration file may not be the 
best place to specify sensitive or secret configuration information. (Nothing prevents you from doing this, though, so 
be careful.)

#### Running a Zero-Hop SubstratumNode locally

Here's all you need to start your zero-hop SubstratumNode:
```
$ sudo SubstratumNode/node/target/release/SubstratumNode --dns-servers 1.1.1.1
```
In the above example, we're using Cloudflare's DNS, `1.1.1.1`, but you can use your preferred DNS.
If you can't choose just one favorite DNS, you can also specify multiple ones, separated by a comma but no space (`,`).

_Why do we specify `--dns-servers`? SubstratumNodes still need to talk to the greater Internet.
See [the ProxyClient README](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node/src/proxy_client)
for more information._

#### Running a Decentralized SubstratumNode locally

Decentralized operation is much more complex than zero-hop operation, so there are many more options that are available.

In order to run decentralized, SubstratumNode needs at least an earning wallet (an Ethereum wallet into which other nodes
will make payments for the services your node provides). If you plan to use your node to consume data with a browser
or other network application, it will also need to be configured with a funded consuming wallet (an Ethereum wallet
from which it will make payments for the services other nodes provide).

Configuring wallets is not a trivial task, so SubstratumNode provides two special execution modes to help you do this, in
addition to the normal long-running Service mode.

1. __Generate mode -__ When you start SubstratumNode in Generate mode, it will generate a new BIP39 mnemonic phrase compatible 
with wallet software (*e.g.* Metamask, MEW) or hardware devices (*e.g.* Ledger, Trezor) and new earning and consuming wallets
for you based on BIP44 derivation paths. It will display this information on the console, and immediately terminate.
You **MUST** record the mnemonic phrase exactly as displayed along with the mnemonic passphrase you provide and 
keep it in a secure location. When it is displayed, that is your only opportunity to record the words. For security 
purposes they cannot be displayed again. Record the words on paper, etch them in metal or stone and secure them in a safe
deposit box or other secure offsite location. Do not run with administrative privileges (`sudo` on Linux and macOS, a command
window started as Administrator in Windows).

1. __Recover mode -__ If you already have existing earning and consuming wallets that you'd like SubstratumNode to use, you
can start it in Recover mode and tell it about those wallets. It will store the information you give it and immediately
terminate. Do not run with administrative privileges (`sudo` on Linux and macOS, a command window started as Administrator in
Windows).

1. __Service mode -__ When started in Service mode, SubstratumNode will come up, join the Substratum Network, and start
serving and consuming clandestine data until you stop it. Since Service mode requires listening on low-numbered
restricted ports, starting SubstratumNode in Service mode requires administrative privilege (`sudo` on Linux and macOS, a
command window started as Administrator in Windows).

##### Generate and Recover Modes

* `--generate-wallet` (Generate mode only) This flag tells SubstratumNode that it will be operating in Generate mode. No
value can be supplied for this flag, and it cannot be given in the environment.

* `--recover-wallet` (Recover mode only) This flag tells SubstratumNode that it will be operating in Recover mode. No
value can be supplied for this flag, and it cannot be given in the environment.

* `--help` Displays help for the mode you're running in. Used by itself, it will show help for Service mode; used
with `--generate-wallet` or `--recover-wallet` it will show help for the appropriate initialization mode. Cannot be 
specified in the environment.

* `--data-directory <DIRECTORY>` Operates the same for initialization modes as for Service mode. See below.

* `--consuming-wallet <BIP44 DERIVATION PATH>` The HD derivation path for the consuming wallet that either 
you're directing to be generated (Generate mode) or you already have (Recover mode). It defaults to m/44'/60'/0'/0/0. 
Note that a derivation path will almost always have single quotes in it, so double-quote it on the command
line to avoid unpleasantness.

* `--earning-wallet <WALLET-ADDRESS> | <BIP44 DERIVATION PATH>` 
If you specify this with an Ethereum address ("0x" followed by 40 hexadecimal digits), SubstratumNode will use the address to
identify your earning wallet. If you specify a derivation path, SubstratumNode will use the mnemonic phrase (either the one
you specify in Recover mode or the one node generates in Generate mode) and this derivation path to compute the
address of your earning wallet. If you don't specify `--earning-wallet` at all, node will use a default of
m/44'/60'/0'/0/1. Note that a derivation path will almost always have single quotes in it, so double-quote it 
on the command line to avoid unpleasantness.

* `--language <English | 中文(简体) | 中文(繁體) | Français | Italiano | 日本語 | 한국어 | Español>` HD wallets spring from a 
single master keypair, which takes friendly form as a "mnemonic
phrase" consisting of some number of standardized words in a particular order. Each word represents a
particular bit pattern in the keypair. SubstratumNode supports mnemonic phrases in a variety of languages.
Specify the language in which you wish the mnemonic phrase to be generated (Generate mode) or in which
you wish to supply the mnemonic phrase (Recover mode) with the `--language` parameter. Defaults to
English.

* `--word-count <12 | 15 | 18 | 21 | 24>` (Generate mode only) The mnemonic phrase that represents your master keypair can have
different numbers of words in it. Shorter phrases are easier to remember; longer phrases are more secure.
This is the number of words you want to be in the mnemonic phrase SubstratumNode generates for you. Default is 12 for the 
Ropsten testnet, and 24 for the Ethereum mainnet. 

* `--mnemonic <BIP39 WORDS>` (Recover mode only) Specify the mnemonic phrase from which the consuming and earning wallets
are derived. Remember to double-quote the phrase. Do not include the mnemonic passphrase here. Keep in mind
that this is highly sensitive information; if it is compromised, the entire derivation tree is compromised.
You can provide it on the command line if you wish, but keep in mind that command lines can frequently be
seen by anyone who has enough privilege to get a list of running processes on the system. If you start SubstratumNode
in Recover mode and don't supply a `--mnemonic`, you'll be prompted to type it in at the console. This is
much safer.

* `--mnemonic-passphrase <MNEMONIC-PASSPHRASE>` This is a word or phrase that you make up that is used along with the mnemonic
passphrase to generate the keypair that will serve as the root of your derivation tree. If you're in
Recover mode and the mnemonic phrase you're entering doesn't have a mnemonic passphrase, you can leave it
blank, but if you're in Generate mode we recommend that you select a passphrase to further obfuscate your
seed. You'll only have to enter this whenever you generate or specify your mnemonic phrase. It's sensitive
information, and if you don't specify it on the command line, you'll be prompted for it at the console. This
is much safer.

* `--wallet-password <PASSWORD>` SubstratumNode has to store your root keypair in a database on disk. However, since it's
sensitive information, it's important that it not be available to anyone who might hack into or steal your
computer. Therefore, SubstratumNode needs to use a password to encrypt the key. SubstratumNode won't store the password,
so you'll need to choose it when you initialize in Generate or Recover mode, and then supply it again whenever
it's needed in Service mode.

##### Service Mode

* `--help` Displays command help and stops. Does not require administrative privilege. Cannot be specified in the
environment or config file.

* `--version` Displays the currently-running version of SubstratumNode and stops. Does not require 
administrative privilege. Cannot be specified in the environment or config file.

* `--blockchain-service-url <URL>` A required URL that should point to an Infura, Geth, or Parity HTTP endpoint. Eventually, 
SubstratumNode will direct blockchain traffic through the Substratum Network when the parameter is not specified, allowing other 
nodes to talk to the blockchain on your behalf.

* `--chain <dev | mainnet | ropsten>` The blockchain network SubstratumNode will configure itself to use. You must ensure the 
Ethereum client specified by --blockchain-service-url communicates with the same blockchain network.

* `--ip <IP ADDRESS>` This is the public IP address of your SubstratumNode: that is, the IP address at which other
SubstratumNodes can contact yours. If you're in a fairly standard residential situation, then this will be the IP
address issued to your router by your ISP, and in order to receive data you'll need to create holes in your router's
firewall to enable incoming data to reach you on your clandestine ports (see below).  In the future, this will be taken
care of for you (if you haven't turned off UPnP on your router), but right now it's manual.

* `--dns-servers <IP ADDRESS>,...` This is the same list of DNS servers needed for zero-hop operation. Whenever your
SubstratumNode is used as an exit node, it will contact these DNS servers to find the host the client is trying to reach.

* `--neighbors <PUBLIC KEY>:<IP ADDRESS>:<PORT>[;<PORT>;...][,<PUBLIC KEY>:<IP ADDRESS>:<PORT>[;<PORT>;...],...`
This is how you tell SubstratumNode about its initial neighbors. You can specify as many neighbors as you like, with the
descriptors separated by commas but no spaces. The `<PUBLIC KEY>` in a descriptor is the Base64-encoded public key of the
neighbor in question. The `<IP ADDRESS>` is the public IP address of that neighbor, and the `<PORT>` numbers are the
clandestine ports on which the neighbor is listening.  If the neighbor node is one you're running yourself, you'll see it
print this information to the console when it comes up.  If it's somewhere else on the Internet, you'll probably receive
this information in an email or chat message to copy/paste onto your command line.

* `--clandestine-port <PORT>`
This is an optional parameter. If you don't specify a clandestine port, your node will use the same clandestine port it
used last time it ran, if that port is still available. If the port is no longer available, SubstratumNode will refuse to
start until either it is available or until you specify a `--clandestine-port`, whereupon it will use the new port
every time it starts. If it's a new installation, it will select a random unused clandestine port between 1025 and 9999,
and use that every time. Whenever you specify `--clandestine-port`, the port you specify will keep being used until
you reinstall or specify a different one. You can specify any port between 1025 and 65535. Whatever the clandestine port
is, it will be printed in the log and to the console as part of the node descriptor when SubstratumNode starts up. Note: 
This is a temporary parameter; the concept of a special clandestine port will go away someday, and node descriptors will
look different.

* `--log-level <off | error | warn | info | debug | trace>`
SubstratumNode has the potential to log a lot of data. (A _lot_ of data: a busy node can fill your disk in a few 
minutes.) This parameter allows you to specify how much of that potential will be realized. `trace` will encourage 
SubstratumNode to reach its full potential, and should probably only be used when you're going to run SubstratumNode 
for a few seconds to try one thing that's been giving you problems, and then shut it off to look at the logs. `error` 
logs only the most serious of errors, and the other values are in-between compromise points. Default is `warn`.

* `--ui-port <PORT>`
This is how you tell SubstratumNode which port it should listen on for local WebSocket connections to the UI gateway. 
This allows SubstratumNode to be controlled and inspected by other programs, such as the SubstratumNode UI. The default 
port is 5333; in most cases, this will not need to be changed.

* `--data-directory <DIRECTORY>`
This is the directory in which SubstratumNode will keep the state that needs to persist from run to run. If it's not specified, the
default is `$XDG_DATA_HOME/Substratum/<chain-name>` or `$HOME/.local/share/Substratum/<chain-name>` on Linux, 
`%APPDATA%\Substratum\<chain-name>` on Windows, and `$HOME/Library/Application Support/Substratum/<chain-name>` on macOS where 
`chain-name` is either `ropsten` or `mainnet` (see `--chain` parameter for more information). If it is specified but doesn't 
exist, SubstratumNode will try to create the directory and abort if it fails. If persistent state exists in the directory, 
but it was created by a version of SubstratumNode that is incompatible with the version you're trying to start, SubstratumNode 
will abort. If this is the case, either remove the existing state and restart SubstratumNode, or specify a different 
`--data-directory` directory.

* `--config-file <FILENAME OR PATH>`
Rather than specifying the same parameter values over and over when you start SubstratumNode in Service mode, you can put parameters that
rarely or never change in a TOML file as strings or numeric values. The entries in the config file should have
exactly the same names they would have on the command line, without the `--` prefix. For example, instead of specifying

  `--dns-servers 1.1.1.1,8.8.8.8`

  on the command line, you could put

  `dns-servers = "1.1.1.1,8.8.8.8"`

  in the config file.

  If you name the file `config.toml` and put it in
either the default data directory or the directory specified by `--data-directory` (see above), SubstratumNode will find and
employ it automatically. If it has a different name or location, specify that with `--config-file`. If the path you
specify is relative, it will be interpreted starting with the active data directory. If it's absolute, it will be
evaluated without reference to the data directory. If you specify a `--config-file` and SubstratumNode can't find it, it will
abort its startup with an error.

* `--consuming-private-key <64-CHARACTER HEX KEY>`
This allows you to specify the private key of your consuming wallet without having it related to your earning wallet by
derivation path. While this method is fully functional, it's mostly useful for testing. If you do use it, keep in mind
that your consuming wallet private key is sensitive information: anyone who gets hold of it can drain all your funds.
It's best to specify it in the environment (as SUB_CONSUMING_PRIVATE_KEY) rather than on the command line or in the
config file. You won't be allowed to use this parameter if you've already specified a consuming wallet derivation path
in Generate or Recover mode; and if you do use this parameter, you must specify exactly the same private key every time
you run your SubstratumNode. If you always use `--consuming-private-key` and `--earning-wallet` with an address, you can use SubstratumNode in
Service mode without having to go through Generate or Recover mode first, and without supplying a wallet password.

* `--earning-wallet <WALLET-ADDRESS>` 
This is an Ethereum address ("0x" followed by 40 hexadecimal digits) which SubstratumNode will use to identify your earning 
wallet. You must not have generated or recovered with an earning wallet derivation path, and you must
always specify the same Ethereum address for your earning wallet.

* `--gas-price <GAS-PRICE>`
The gas price is the amount of Gwei you will pay per unit of gas used in a transaction.

  If you don't have an earning wallet set up at all, and you don't specify this either, a default earning wallet will be
used, in which case the funds you earn will go to Substratum instead of to you: so unless you're in a philanthropic mood,
you should be sure to set up or specify your earning wallet.

In order to run decentralized, the SubstratumNode _must_ know the IP address others can use to contact it. Therefore,
you must supply `--ip`. If you don't supply `--ip`, your node will come up in zero-hop mode and never route through
any other nodes.

If you're starting the very first SubstratumNode in your Substratum network, then you don't have to tell your node about 
any preexisting network; but otherwise, you'll need to specify `--neighbors` so that your node will know how to join the
network that is already in place.

Your home network is behind your internet provider's router and a public IP address. Other nodes in the Substratum Network
will contact your node through your public IP address, requiring at least one port to be forwarded on your router. The 
SubstratumNode Gossip protocol "gossips" to other nodes the clandestine port you are listening on, and it is that port 
you will need to open. When your node is started it will write its descriptor to the console and the log, giving the clandestine
port it is using; you will need to forward that port from your router to your computer's IP address.

Forwarding ports on your router is somewhat technical. At a minimum, you should know how to log in to your router in 
order to make changes to its configuration. The process is interchangeably called forwarding a port, opening a port,
or mapping a port, and may be labeled as such in the router's interface. Assigning a static IP address for your computer
will make this process easier, as otherwise your IP address can change each time your computer restarts or you restart
the network interface. There are many guides that you can find on the Internet by searching for "Port Forwarding" or
"How to Port Forwarding". Here is an example: [PortForward.com](https://portforward.com)

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
leave them open against the next time you run: your node will pick different clandestine ports the next time.

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

* Routing Failure - `internal_error`: If your node is not yet "warmed up" enough in the Substratum Network to see a
large enough neighborhood to be able to create a clandestine route that meets your specifications, it will raise a
TLS `internal_error` Alert. This will probably be displayed by your browser as some sort of protocol error--which,
strictly speaking, it is. If this happens, just wait awhile for your node and the Substratum Network to Gossip with
each other and spread around the necessary information. Then try reloading the page.

* DNS Resolution Failure - `unrecognized_name`: Even though you contact websites at names like `google.com` and
`facebook.com`, the real Internet operates on the basis of IP addresses (like `172.217.6.14` and `31.13.66.35`).
Before it's useful for retrieving data, your server name has to be translated into an IP address. This is the job of a
DNS server. Much of Internet censorship consists of crippling the DNS servers you have available to you so that they
can't give you the correct IP address for the server name you're seeking. SubstratumNode captures the DNS queries your
browser makes and forwards them across the Substratum Network to some other node that hopefully has access to a
non-censored DNS server that _does_ know the IP address you want. But this is a complex task and it may fail. For
example, perhaps you typed the server name wrong, and _nobody_ knows an IP address it matches. Or perhaps your
SubstratumNode guessed wrong, and the exit node to which it forwarded your DNS query is also handicapped by a censored DNS
and can't find it either. In either case, SubstratumNode will send your browser a TLS `unrecognized_name` alert, which
your browser will probably present to you as some form of can't-find-host error. If you reload the page, SubstratumNode
will try to select a different exit node, if available--one that hasn't failed to resolve a DNS query--for the next 
attempt, which might bring you better fortune. Of course, if you _have_ typed the name wrong, just reloading the page
will take another innocent exit node out of circulation and make it even harder for you to get where you want to go.

# Disclosure

We run tests on every push to `master` on these platforms:
- Ubuntu 16.04 Desktop 64-bit
- MacOS High Sierra
- Windows 10 64-bit

SubstratumNode doesn't reliably build on 32-bit Windows due to issues with the build tools for that platform. We 
recommend using a 64-bit version to build.

We do plan to release binaries that will run on 32-bit Windows, but they will likely be built on 64-bit Windows.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
