# `proxy_server`

## Purpose
The purpose of `proxy_server` is to convert regular (non-clandestine) requests into CORES packages for the MASQ Network,
and convert CORES packages from the MASQ Network back into regular (non-clandestine) responses.

When you use the MASQ Network, the ProxyServer on your local MASQ Node is the first stop.
ProxyServer acts as a front end for the MASQ Network, appearing to your browser to be the server
to which it's trying to connect. It converts your regular TCP request into a MASQ CORES package and sends it out 
onto the MASQ Network. When the response comes back, ProxyServer unwraps it and gives it back to the requesting entity 
on your host machine.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/MASQ-Project/Node/tree/master/node)
is a better place to start.

Copyright (c) 2022, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
