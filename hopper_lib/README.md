# hopper_lib
Micro routing for SubstratumNetwork traffic

## Purpose
The purpose of `hopper_lib` is to interpret CORES packages, determining their next destination --
either inside the current SubstratumNode (i.e. to the ProxyServer or the ProxyClient)
or on to the next SubstratumNode in its Route.

It is built as a library, and is not intended as a standalone program.
It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
