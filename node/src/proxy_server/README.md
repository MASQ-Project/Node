# proxy_server

## Purpose
The purpose of `proxy_server` is to convert regular (non-clandestine) requests into CORES packages for the SubstratumNetwork,
and convert CORES packages from the SubstratumNetwork back into regular (non-clandestine) responses.

When you use the SubstratumNetwork, the ProxyServer on your local SubstratumNode is the first stop.
ProxyServer converts your regular TCP request into a Substratum CORES package and sends it out onto the SubstratumNetwork.
When the response comes back, ProxyServer unwraps it and gives it back to the requesting entity on your host machine.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
