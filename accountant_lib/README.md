# accountant_lib
Maintenance of SUB accounts for SubstratumNode.

## Purpose
The purpose of `accountant_lib` is to keep track of SUB owed to other Nodes by the local Node and SUB owed to the local
Node by other Nodes, and to interact with the blockchain to pay accounts payable and detect payment of accounts
receivable, and also to detect and report financially-related deadbeat or suspicious behavior by other Nodes.

It is built as a library, and is not intended as a standalone program.
It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
