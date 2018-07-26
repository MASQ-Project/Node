# dns_utility
Utility for helping to change DNS on a user's local machine.

## Purpose
The purpose of `dns_utility` is to be the OS-agnostic tool that the SubstratumNode user interface will use to examine
and manage the DNS settings of a user's machine for routing its TCP communications over the Substratum Network.

It is built as a utility, and can be run from the command line. There are two main parameters which require privilege escalation. They are:

- `subvert` - Subverts a user's DNS settings by changing it to the local machine so that it relies on the Substratum Network for resolution.
- `revert` - Reverts a user's DNS settings to the previous configuration.

The other parameters are:
- `inspect` - Shows a user's current DNS settings.

The `dns_utility` can be run locally from the command line.

Mac/Linux:
```
$ cd <path to workspace>/SubstratumNode/dns_utility/target/release
$ dns_utility inspect
192.168.0.1
192.168.0.2
$ sudo dns_utility subvert
$ dns_utility inspect
127.0.0.1
$ sudo dns_utility revert
$ dns_utility inspect
192.168.0.1
192.168.0.2
$
```

Windows (running with admin privilege required by 'subvert' and 'revert'):
```
> cd <path to workspace>\SubstratumNode\dns_utility\target\release
> dns_utility inspect
192.168.0.1
192.168.0.2
> dns_utility subvert
> dns_utility inspect
127.0.0.1
> dns_utility revert
192.168.0.1
192.168.0.2
>
```

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
