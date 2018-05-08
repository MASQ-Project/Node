# dns_utility
Utility for helping to change DNS on a user's local machine.

## Purpose
The purpose of `dns_utility` is to be the underlying utility that the SubstratumNode user interface will use to toggle a user's machine for 
routing its TCP communications over the Substratum Network.

It is built as a utility, and can be run from the command line. There are two main parameters. They are:

- `subvert` - Subverts a user's DNS settings by changing it to the local machine so that it relies on the Substratum Network for resolution.
- `revert` - Reverts a user's DNS settings to the previous configuration

The `dns_utility` can be run locally from the command line:
```
<path to workspace>/SubstratumNode/dns_utility/target/release/dns_utility subvert
<path to workspace>/SubstratumNode/dns_utility/target/release/dns_utility revert

```

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
