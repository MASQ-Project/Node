# neighborhood
Route generation for MASQ Node

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/MASQ-Project/Node/tree/master/node)
is a better place to start.

## About the "Neighborhood"

Each MASQ Node in the MASQ Network contains a subsystem that we call the Neighborhood. The Neighborhood is
responsible for keeping track of other Nodes in the network, remembering how (and whether) they're connected to one
another, and storing other information about them as well. Our current plan for the future is that we'll also remember 
things like how fast they have proven to be and whether they're acting suspiciously. Also, whenever a consuming Node
wants to send a CORES package through the network, its Neighborhood is responsible for analyzing the network and
determining what route the CORES package should take.

### Gossip

At certain times, the Neighborhood will trigger a round of Gossip. When this happens, the Neighborhood will send a
CORES package to each of the Nodes to which your Node has a direct TCP connection. (Note: this will not cost you any 
routing SUB, because since each of these Nodes is right next to you, no Node
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

As a matter of fact, the best computer on which to run a MASQ Node is one whose public IP _never_ changes: one
whose ISP has granted a static IP address. Failing that, the best way to run a Node is on a non-portable computer that
is using a wired Ethernet connection. (Sending data through a wire keeps it far more secure than broadcasting it through
the air.) Failing _that,_ the best way would be on a WiFi-connected computer that may move around in the territory of a
particular router, but doesn't leave it and is never suspended or hibernated.

#### Warm-Up Delay

Each Node in the network will know the IP addresses of the few Nodes that are directly connected to it, but it will not
know the IP addresses of any other Node in the network. There are a few security-related implications of this.

One thing it means is that it requires a route at least three hops long to make sure that none of the Nodes on the route
knows all the IP addresses in it. Therefore, a route less than three hops long is intrinsically insecure.

Another thing it means has to do with the fact that the exit Node for a two-way route needs to know the public key of
the originating Node, so that it can encrypt the response payload. Therefore, the exit Node should not also know the
IP address of the originating Node; otherwise it would be able to associate request URLs (TLS) or entire request/response
transactions (HTTP) with originating IP addresses.

Hence, the question of whether a Neighborhood can produce valid routes is a complex one. It needs enough Nodes that it
can produce a minimum three-hop route, but not so many connections between Nodes that it can't find an exit Node that isn't 
directly connected.

All this means that it may take a significant interval of time, marked by the periodic arrival and departure of Gossip,
before a newly-started Neighborhood is complete enough to be able to generate routes to allow its owner to originate
traffic. On the other hand, a Neighborhood will be ready to route other people's data as soon as it has two immediate neighbors.
Of course, in order to do so it must be built into a route by another Node, and it may take some time for another Node to assimilate and choose it as well.

### Technical Policies
The generation and integration of Gossip can be somewhat abstruse. Here are some elements of our various algorithms that
might help make it clearer.

#### Types of Gossip
There are three or four types of Gossip, depending on how you count them.

* _Debut_ - When a Node first starts up, and doesn't know anything about the state of the network except information about
itself and the local descriptor of a single neighbor, it will send Debut Gossip to that neighbor. Debut Gossip contains a
single record describing the debuting Node, with the debuting Node's IP address and at least one neighbor link, to the 
target of the Debut. Debut Gossip always arrives from the Node it describes.

* _Introduction_ - An Introduction is how a Node's Debut Gossip is accepted. The Debut target, upon deciding to accept the
debuting Node as a neighbor, will send a packet of Introduction Gossip containing information about itself and one of its
own neighbors that the debuting Node is not currently directly connected to.  It contains the IP addresses of both Nodes--
the introducer and the introducee.

* _Pass_ - Pass Gossip operates just like an HTTP 302 Redirect response. When one Node is trying to Debut from another,
and the target does not want a new neighbor, the target may respond with Pass Gossip, which says, "Not me, but you might
have some luck contacting this Node instead." Pass Gossip contains a single record describing the Node to which the debuting
Node is being relayed, with the relay target's IP address. Pass Gossip always arrives from a _different_ Node than the one
it describes.

* _Update_ - Update Gossip is the most common kind: it contains a partial or complete picture of what the sender knows
about the network. It's sent whenever a Node has reason to believe another Node may not know about a change to the network
that it has just seen. There may be any number of records in Update Gossip. In general, Update Gossip will contain IP
addresses only for Nodes the target already knows the IP addresses for, except in the case of Introductions.

#### Accepting Gossip
* _Debut_ - The response to a Debut depends on the state of the receiver. If the receiver has nothing but itself in its
database, it assimilates the Debut but makes no response, because it wouldn't be able to say anything useful. If the 
receiver has fewer than five Nodes in its database, it will assimilate the Debut and do two things: to the debuting Node
it will send a special Update containing an Introduction to its least-connected neighbor; and to all the other Nodes in
its database, it will send a standard Update. If it has five neighbors already, it will respond to the Debut
with a Pass indicating its least-connected neighbor. [Note: this is inaccurate and should be updated.]

* _Pass_ - The response to a Pass is simple: the receiver just sends a Debut to the Node given in the Relay.

* _Update_ - The receiver of an Update first filters out all the Introductions; then it either incorporates the individual
records into its own database or ignores them, based on whether their version numbers, when compared to the versions of
the Nodes already in its database, show them to be new or obsolete. After this, it goes through the list of Introductions,
if any, and sends a Debut to each of the indicated Nodes. (The introduced Nodes don't go in the database yet; that 
happens only if they respond favorably to the Debut.) [Note: this is inaccurate and should be updated.]
 
* _You Don't Know Me!_ - When Gossip received from other Nodes includes a record about the local Node,
that record is ignored during the acceptance of the Gossip. No other Node knows what's inside the local Node better than
it does. [Note: this is inaccurate and should be updated.]

* _Ragged Edges_ - Gossip consists of information about a list of other Nodes, with each item containing a list of
public keys of the Nodes to which the Node in that item is connected. Many of those connected Nodes may have their own
item in the Gossip list, but some may not. This isn't an error; it's a necessary condition if we're not to send the
entire world in every Gossip message. Of course, a Node cannot use for routing or exit a ragged-edge Node about which 
it knows nothing but its public key. (For one thing, it won't know that Node's service rates.)

* _Standoffishness_ - It's important for security reasons that an exit Node not know the IP address of the originating
Node whose route it's serving. This means that if a Node is too heavily connected, it can have trouble finding a 
qualified exit Node to route through.

#### Producing Gossip
* _Half Neighbors Reported_ - When a Node produces Update Gossip to send, it will mention all its neighbors, both half
neighbors and full neighbors. The one-way relationships turn out to be of no immediate use, but the neighbors are part
of the versioned and signed state of the Node. Consider Nodes A and B, where A is connected to B but B has not yet
connected to A. If A Gossips, say, version 42 of itself with no connection to B (because half-neighbor relationships
are not useful), and then B establishes a return connection to A, A cannot now begin reporting version 42 of itself
with B as its neighbor, because that would be two different states with the same version number. Neither can it
update its version to 43 when B connects back to it, because the change has been in the state of B, not in the state of
A. Changing version numbers without state changes leads to Gossip squalls and storms.

* _Custom Reporting_ - When a Node decides to send Gossip, it doesn't create a single Gossip package and
broadcast it to everyone it knows. Instead, it makes a list of all its half neighbors
and custom-builds a special Gossip package for each one.

* _Introductions_ - When a Node is responding to Debut Gossip, it will send Update Gossip containing the information
in its database, properly censored so that the receiving Node will not receive the IP address of any Node it's not
already directly connected to...with one exception. The responding Node will select its least-connected neighbor and
include that neighbor's IP address in the Update Gossip, thereby making that record an Introduction. Note: it is our
intention in the future to add a security step here: instead of preemptively introducing its neighbor, the responding
Node will instead send a message to that neighbor suggesting an Introduction to the debuting Node, and only actually
send the Introduction if the neighbor responds with assent. [Note: this is inaccurate and should be updated.]

#### Routing
* _Only Full Neighbors_ - Only full-neighbor relationships where each Node in the pair provides a signed statement that it
is connected to the other Node in the pair are used for routing. Half-neighbor relationships with the arrow pointing only
one direction will exist, but they will be useless for routing data, because the Node without an arrow has either not yet
consummated an introduction to the Node with an arrow, in which case it will reject connections from that Node, or it 
has banned that Node for some reason, in which case it will also reject connections from that Node. [Note: this is inaccurate and should be updated.]

Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
