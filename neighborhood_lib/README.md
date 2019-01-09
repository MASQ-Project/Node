# neighborhood_lib
Route generation for SubstratumNode

## Purpose
`neighborhood_lib` is built as a library, and is not intended as a standalone program.
It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.

## About the "Neighborhood"

Each SubstratumNode in the Substratum Network contains a subsystem that we call the Neighborhood. The Neighborhood is
responsible for keeping track of other Nodes in the network, remembering how (and whether) they're connected to one
another, and storing other information about them as well. Currently, for example, we keep track of whether or not
they're bootstrap Nodes and therefore don't route data. Our current plan for the future is that we'll also remember 
things like how fast they have proven to be and whether they're acting suspiciously. Also, whenever a consuming Node
wants to send a CORES package through the network, its Neighborhood is responsible for analyzing the network and
determining what route the CORES package should take.

### Gossip

At certain times, the Neighborhood will trigger a round of Gossip. When this happens, the Neighborhood will send a
CORES package to each of the Nodes to which your Node has a direct TCP connection. (Note: even after we get Monetization
up and running, this will not cost you any routing SUB, because since each of these Nodes is right next to you, no Node
but your own sends any data on your behalf, and therefore there's nobody to pay.) This CORES package will contain part
of what your Node knows about the current state of the network, including what it has learned from other Nodes when
they have sent Gossip to it. When you start a decentralized Node, it needs to know how to locate just one other Node
in the network; but these Gossip messages are how it strengthens its position over time and becomes an integral
participant in the Network.

Of course, since every Node--not just yours--sends Gossip periodically, information about your Node will eventually
percolate out across the network, and information about the farthest reaches of the network will eventually reach your
Node.

### Constraints

In order for this process to work correctly, safely, and profitably, there are certain common-sense constraints on what
a Node should and shouldn't do.

#### Connection

Perhaps chief among these constraints is that you should keep your Node available at the same public IP address as long
as you can. Suppose your Node is listed by another Node's Neighborhood in a route for a CORES package, and by the time the
CORES package arrives at your Node, your Node cannot be contacted in the way the originating Node's Neighborhood expected
it to be. In that case, the CORES package will fail to route, and it will have to be sent again; but
in order to keep itself from making the same mistake, the Node that failed to contact your Node will A) make a note not
to route any more data through your Node, and B) Gossip this information ("Don't route data through me to him; I can't
contact him") out to other Nodes. In this way, even a brief period of disconnection can seriously affect the amount of
(potentially) profitable routing work your Node will be given.

Therefore, it's not a good idea (for example) to suspend a laptop on which a Node is running. It should stay running and
connected as long and steadily as possible. It's also not a good idea to move a Node-running laptop to the service area
of another access point with a different public IP address. We have plans to make certain public-IP changes
survivable, but currently none are. If your public IP address changes, your Node traffic will drop to zero and stay
there; you'll need to kill your Node and restart it to get it back on the Network.

As a matter of fact, the best computer on which to run a SubstratumNode is one whose public IP _never_ changes: one
whose ISP has granted a static IP address. Failing that, the best way to run a Node is on a non-portable computer that
is using a wired Ethernet connection. (Sending data through a wire keeps it far more secure than broadcasting it through
the air.) Failing _that,_ the best way would be on a WiFi-connected computer that may move around in the territory of a
particular router, but doesn't leave it and is never suspended or hibernated.

#### Warm-Up Delay

Each Node in the network will know the IP addresses of the few Nodes that are directly connected to it, but it will not
know the IP addresses of any other Node in the network. There are a few security-related implications of this.

One thing it means is that it requires a route at least three hops long to make sure that none of the Nodes on the route
knows all the IP addresses in it. Therefore, a route less than three hops long is intrinsically insecure. However, since
__the current version of SubstratumNode is not intended to be secure__ anyway, we have a default route-length minimum of
two hops rather than three, because it makes testing easier while still presenting all the conditions we need to test.

Another thing it means has to do with the fact that the exit Node for a two-way route needs to know the public key of
the originating Node, so that it can encrypt the response payload. Therefore, the exit Node should not also know the
IP address of the originating Node; otherwise it would be able to associate request URLs (TLS) or entire request/response
transactions (HTTP) with originating IP addresses.

Hence, the question of whether a Neighborhood can produce valid routes is a complex one. It needs enough Nodes that it
can produce a minimum two-hop (three-hop eventually) route, but not so many connections between Nodes that it can't find
an exit Node that isn't directly connected.

All this means that it may take a significant interval of time, marked by the periodic arrival and departure of Gossip,
before a newly-started Neighborhood is complete enough to be able to generate routes to allow its owner to originate
traffic. On the other hand, a Neighborhood will be ready to route other people's data as soon as it has two immediate neighbors
that are not bootstrap Nodes. Of course, in order to do so it must be built into a route by another Node, and it may take
some time for another Node to assimilate and choose it as well.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
