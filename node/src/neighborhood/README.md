# `neighborhood`
Route generation for MASQ Node

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/MASQ-Project/Node/tree/master/node)
is a better place to start.

## About the Neighborhood

Each MASQ Node in the MASQ Network contains a subsystem that we call the Neighborhood. The Neighborhood is
responsible for keeping track of other Nodes in the network, remembering how (and whether) they're connected to one
another, and storing other information about them as well. Our current plan for the future is that we'll also remember 
things like how fast they have proven to be and whether they're acting suspiciously. Also, whenever a consuming Node
wants to send a CORES package through the network, its Neighborhood is responsible for analyzing the network and
determining what route the CORES package should take.

### Gossip

At certain times, the Neighborhood will trigger a round of Gossip. When this happens, the Neighborhood will send a
CORES package to each of the Nodes to which your Node has a direct TCP connection. (Note: this will not cost you any 
routing MASQ, because since each of these Nodes is right next to you, no Node but your own sends any data on your 
behalf, and therefore there's nobody to pay.) This CORES package will contain part of what your Node knows about the 
current state of the network, including what it has learned from other Nodes when they have sent Gossip to it. When 
you start a decentralized Node, it needs to know how to locate just one other Node in the network; but these Gossip 
messages are how it strengthens its position over time and becomes an integral participant in the Network.

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
is using a wired Ethernet connection. (Sending data over a wire keeps it far more secure than broadcasting it through
the air.) Failing _that,_ the best way would be on a WiFi-connected computer that may move around in the territory of a
particular router, but doesn't leave it and is never suspended or hibernated.

#### Warm-Up Delay

Each Node in the network will know the IP addresses of the few Nodes that are directly connected to it, but it will not
know the IP addresses of any other Node in the network.

One security-related implication of this is that it requires a route at least three hops long to make sure that none of 
the Nodes on the route know all the IP addresses in it. Therefore, a route less than three hops long is intrinsically 
insecure.

Hence, the question of whether a Neighborhood can produce valid routes amounts to the question of whether it can find
enough Nodes that it can produce a minimum three-hop route.

This means that it may take a significant interval of time, marked by the periodic arrival and departure of Gossip,
before a newly-started Neighborhood is complete enough to be able to generate routes to allow its owner to originate
traffic. On the other hand, a Neighborhood will be ready to route other people's data as soon as it has two immediate 
neighbors. Of course, in order to do so it must be built into a route by another Node, and it may take some time for 
another Node to assimilate and choose it as well.

### Technical Policies
The generation and integration of Gossip can be somewhat abstruse. Here are some elements of our various algorithms that
might help make it clearer.

#### Types of Gossip
There are three or four types of Gossip, depending on how you count them.


* _Debut_ - When a Node first starts up, and doesn't know anything about the state of the network except information 
  about itself and the local descriptor of a single neighbor, it will send __Debut__ Gossip to that neighbor. Debut 
  Gossip contains a single record describing the debuting Node, with the debuting Node's IP address and at least one 
  neighbor link, to the target of the Debut. Debut Gossip always arrives from the Node it describes.


* _Introduction_ - An __Introduction__ is how a Node's Debut Gossip is accepted. The Debut target, upon deciding to 
  accept the debuting Node as a neighbor, will send a packet of Introduction Gossip containing information about itself 
  and one of its own neighbors that the debuting Node is not currently directly connected to.  It contains the IP 
  addresses of both Nodes--the introducer and the introducee.


* _Pass_ - __Pass__ Gossip operates just like an HTTP 302 Redirect response. When one Node is trying to Debut from 
  another, and the target does not want a new neighbor, the target may respond with Pass Gossip, which says, "Not me, 
  but you might have some luck contacting this Node instead." Pass Gossip contains a single record describing the Node 
  to which the debuting Node is being relayed, with the relay target's IP address. Pass Gossip always arrives from a 
  _different_ Node than the one it describes.


* _Standard_ - __Standard__ Gossip is the most common kind: it contains a partial or complete picture of what the sender 
  knows about the network. It's sent whenever a Node has reason to believe another Node may not know about a change to 
  the network that it has just seen. There may be any number of records in Standard Gossip. In general, Standard Gossip 
  will contain IP addresses only for Nodes the target already knows the IP addresses for, except in the case of 
  Introductions.

#### Accepting Gossip

* _Debut_ - The response to a Debut depends on the connectedness of the receiver and its neighbors. First, the receiver
  looks for a more-appropriate neighbor to handle the Debut: specifically, it looks for a neighbor that already has
  three or more neighbors (including the receiver), but fewer than the receiver. If it finds such a neighbor, it
  responds to the sender with Pass Gossip referring it to that neighbor.
  
  If there is no more-appropriate neighbor, the receiver tries to accept the Debut itself, which it will do unless it
  already has five neighbors, which is the maximum possible.
  
  If the receiver already has five neighbors, it will attempt to locate its least-connected neighbor and respond to the 
  sender with Pass Gossip referring it to that neighbor.
  

* _Introduction_ - The receiver of an Introduction incorporates the introducer and introducee into its database and
  sends out a packet of Standard Gossip describing the change.


* _Pass_ - The response to a Pass is simple: the receiver just sends a Debut to the Node mentioned in the Pass.
  

* _Standard_ - The receiver of Standard Gossip incorporates any changes into its database, if it can. If the Standard
  Gossip did require changes to the database, those changes are broadcast to the receiver's neighbors via more
  Standard Gossip packets.
 

* _You Don't Know Me!_ - When Node A sends Gossip to Node B, it does not include any information about Node B in that
  Gossip, because Node B will know everything about itself better than Node A does.
  

* _Ragged Edges_ - Gossip consists of information about a list of other Nodes, with each item containing a list of 
  public keys of the Nodes to which the Node in that item is connected. Many of those connected Nodes may have their 
  own item in the Gossip list, but some may not. This isn't an error; it's a necessary condition if we're not to send 
  the entire world in every Gossip message. Of course, a Node cannot use for routing or exit a ragged-edge Node about 
  which it knows nothing but its public key. (For one thing, it won't know that Node's service rates.)
  

* _Malefactors_ - There are ways Nodes do Gossip, and ways Nodes don't do Gossip. If the Gossip acceptor finds Gossip
  that is nonstandard or deceptive in some way, it will impose a Malefactor Ban on the sender, which means that it
  will 1) disconnect from the Malefactor, if it's a neighbor; 2) send out Standard Gossip showing the disconnection
  (so that other Nodes will not compute routes through the receiver requiring communication with the Malefactor);
  3) make a note of the Malefactor in the database; 4) forever after refuse to connect to the Malefactor; and 5)
  forever after refuse to accept any connections from the Malefactor.

#### Producing Gossip

* _Signing_ - When a Node produces information about itself for Gossip, it cryptographically signs that information so
  that Nodes that receive that Gossip, either directly or indirectly, can know that it was sourced by the Node it
  describes, and was not forged by a rogue Node.  One consequence of this is that the Neighborhood Database must
  contain two versions of each Node's information: one in a complex memory structure that can be directly used for
  operations, and one in a block of binary bits, along with a signature, that can be placed in Gossip packets.
  Reconstituting the binary bits from the complex memory structure turns out to carry a significant risk that the
  result won't be a bit-perfect copy of the incoming block, which would invalidate the signature and result in an
  instant avalanche of Malefactor bans.

  
* _Half and Full Neighbors_ - If Node A is connected to Node B and Node B is connected to Node A, then A and B are
  full neighbors, and network data can flow back and forth between them. If Node C is connected to Node D, but Node D 
  is not connected to Node C, then D is C's half neighbor, and C is not D's neighbor at all. No network data can flow
  in either direction between C and D.
  
  This half-neighbor state may occur because one of the Nodes is in the process of connecting to the Network and
  hasn't completed the process yet; or it may be because one of the Nodes has a Malefactor ban on the other; or it
  may occur because one of the Nodes has gone down. In any case, as long as its Neighborhood Database shows only a
  half-neighborship between two Nodes, no Node will compute a route for data that involves a segment from one of
  those Nodes and the other.
  

* _Versions_ - One of the aspects of each Node that's communicated in its Gossip is its version number. Every Node
  comes up with a version of 1; whenever something about that Node changes that needs to be Gossipped, it will
  increment its version number by one. This way, recipients of Gossip can quickly tell whether they need to update
  their Neighborhood Databases by checking the incoming version number of a Node with the version number that is in
  their Neighborhood Database record. If the incoming version number is higher, then the Node record needs to be
  updated, and Gossip about the update generated. If the incoming version number is the same or lower, that particular
  Node record is ignored, and if all the Node records in the Gossip are ignored, no Gossip will be sent.


* _No Tattling_ - There is deliberately no space in the Gossip protocol for Node A to tell Node B anything it thinks
  about Node C. The only thing A can tell B about C is the signed Node record produced by C; and of course A can't alter
  that record in any way, or B will notice that C's signature doesn't match, and will subject A to a Malefactor ban.
  
  Note, of course, that C may well be lying about itself in some way in that signed Node record; but it can only lie
  about itself, not about any other Node.
  
  On the one hand, it might be useful for A to be able to tell B that A is suspicious of C for some reason; however,
  any capability of that sort would be instantly abused by attackers in an attempt to take down the network. Therefore:
  the only mark of disapproval Node A can transmit to Node C about Node B is the fact that Node A has withdrawn its
  connection to Node B. This is because Node A's connections are part of its Node record, which it can sign and Gossip.
  B's connection to A is part of B's Node record, so A can't modify that; but the fact that A can disrupt the
  full-neighbor connection to B means that it has veto power over the network segment between A and B.


* _Custom Reporting_ - When a Node decides to send Gossip, it doesn't create a single Gossip package and broadcast it 
  to everyone it knows. Instead, it makes a list of all its half neighbors and custom-builds a special Gossip package 
  for each one.

Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
