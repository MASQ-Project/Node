# proxy_client

## Purpose
The purpose of `proxy_client` is to convert CORES packages from the SubstratumNetwork into regular (non-clandestine) requests,
and convert the regular (non-clandestine) responses back into CORES packages for the SubstratumNetwork.

When you use the SubstratumNetwork, the ProxyClient on some distant SubstratumNode is the component that does the
non-clandestine communication with the greater Internet.
ProxyClient converts your CORES package back into a regular request, gets the response, and wraps it in a new
CORES package. That CORES package goes back onto the SubstratumNetwork to continue on the Route back to you.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
