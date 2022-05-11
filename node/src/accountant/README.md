# `accountant`
Maintenance of Accounts Payable and Accounts Receivable for MASQ Node.

## Purpose
The purpose of `accountant` is to keep track of MASQ owed to other Nodes by the local Node and MASQ owed to the local
Node by other Nodes, and to interact with the Blockchain Bridge to pay accounts payable and detect payment of accounts
receivable, and also to detect and report financially-related deadbeat or suspicious behavior by other Nodes.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/MASQ-Project/Node/tree/master/node)
is a better place to start.

Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
