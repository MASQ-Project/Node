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
- `status` - Tells whether a user's DNS has been subverted or not.

The `dns_utility` can be run locally from the command line.

Mac/Linux:
```
$ cd <path to workspace>/SubstratumNode/dns_utility/target/release
$ dns_utility inspect
192.168.0.1
192.168.0.2
$ dns_utility status
reverted
$
$ sudo dns_utility subvert
$ dns_utility inspect
127.0.0.1
$ dns_utility status
subverted
$
$ sudo dns_utility revert
$ dns_utility inspect
192.168.0.1
192.168.0.2
$ dns_utility status
reverted
$
```

Windows (running with admin privilege required by 'subvert' and 'revert'):
```
> cd <path to workspace>\SubstratumNode\dns_utility\target\release
> dns_utility inspect
192.168.0.1
192.168.0.2
> dns_utility status
reverted
>
> dns_utility subvert
> dns_utility inspect
127.0.0.1
> dns_utility status
subverted
>
> dns_utility revert
192.168.0.1
192.168.0.2
> dns_utility status
reverted
>
```

It probably isn't the most interesting place to begin digging into our code;
[node](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node)
is a better place to start.


Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
