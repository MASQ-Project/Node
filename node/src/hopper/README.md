# `hopper`
Micro routing for MASQ Network traffic

## Purpose
The purpose of `hopper` is to interpret CORES packages, determining their next destination --
either inside the current MASQ Node (i.e. to the `ProxyServer` or the `ProxyClient`)
or on to the next Node in its Route.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/MASQ-Project/Node/tree/master/node)
is a better place to start.

Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
