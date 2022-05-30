# `proxy_client`

## Purpose
The purpose of `proxy_client` is to convert CORES packages from the MASQ Network into regular (non-clandestine) requests,
and convert the regular (non-clandestine) responses back into CORES packages for the MASQ Network.

When you use the MASQ Network, the ProxyClient on some distant MASQ Node is the component that does the
non-clandestine communication with the greater Internet. ProxyClient acts as a back end for the MASQ Network, appearing
to the server to be your browser. It converts the CORES package from your Node's ProxyServer back into a regular 
request, gets the response, and wraps it in a new CORES package. That CORES package goes back onto the MASQ Network 
to continue on the Route back to your Node's ProxyServer.

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/MASQ-Project/Node/tree/master/node)
is a better place to start.

Copyright (c) 2022, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
