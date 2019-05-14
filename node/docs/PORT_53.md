# Port 53 Problems?

## Identification
When you try to start your SubstratumNode, do you see a message that looks something like one of these?

```
thread 'main' panicked at 'Cannot bind socket to V4(0.0.0.0:53): Os { code: 10048, kind: AddrInUse, message: "Only one usage of each socket address (protocol/network address/port) is normally permitted." }'
```

```
thread 'main' panicked at 'Cannot bind socket to V4(0.0.0.0:53): Error { repr: Os { code: 98, message: "Address already in use" } }'
```

The important parts of this message are the "`V4(0.0.0.0:53)`" part (especially the `:53`) and the "`Only one usage of each socket address`..."
or "`Address already in use`" part.  Different operating systems may produce slightly different messages.

If you see both of those parts in the message, then you are definitely afflicted with the __Port 53 Problem__. If
you see only one of them, you're _probably_ afflicted with the __Port 53 Problem__. If you see neither of them,
these instructions can't help you; sorry.

If you don't care about what the problem is or why it happens, and you just want to know how to fix it, skip down to 
the __Solutions__ section.

## Background

### Windows
Windows includes a service called Internet Connection Sharing (ICS) that listens on port 53. It's a somewhat dated service
from the days before widespread WiFi availability that allows you to make your Windows machine a nexus through which
other people can connect their machines to the Internet. If you're not already aware that you're doing this, you
probably don't need to have ICS active.

### Linux
Some Linux distributions (we know about Ubuntu Desktop >=16.04 and some versions of Mint, but there are probably others)
come with an installed utility called `dnsmasq`. This utility is intended to let folks with small home LANs give 
intelligible names to their computers, printers, TVs, DVRs, mobile devices, and other Internet-enabled devices, rather 
than having to reference them by numeric IP address.  You may instead have a distribution (for example Ubuntu 18.04)
that uses `systemd-resolved` for this purpose.  We'll generically call this dns caching.

DNS caching works by putting up a small DNS server on your local machine that fields name-resolution requests for things
like "LivingRoomTV" and returns IP addresses like 192.168.0.47.  This means that when you want to control your TV
from upstairs, or watch its video feed, or whatever it allows you to do remotely, you can call it "LivingRoomTV"
(or select it from a list) rather than having to remember its IP address (which may change unexpectedly).

### In General
Any software that uses a DNS server to convert an intelligible name into an IP address will contact that
DNS server on Port 53; it's part of the widely-accepted DNS protocol. Therefore, every DNS server must listen on
Port 53 for requests if it expects to receive any.

Unfortunately, only one server can listen on Port 53 (or any port) at one time.

## The Problem
SubstratumNode also includes a small DNS server that allows applications on your computer to send and receive data on
the Substratum Network. Since this is a DNS server, it must also listen on Port 53. This means that a DNS-subverting
SubstratumNode and preexisting port 53 software are irredeemably inimical to one another and cannot ever operate
simultaneously on the same computer.

Eventually, SubstratumNode will be able to operate in regimes other than DNS subversion, which means that under some
circumstances, and in the presence of certain sacrifices, it will be compatible with other port 53 software;
but that's in the future, not the present.

## Solutions

### Windows
Internet Connection Sharing can be an annoyance. We had problems with it starting spontaneously after we stopped it,
and reenabling itself and starting after we disabled it, and coming back into action over a reboot, in all cases
monopolizing port 53 and preventing SubstratumNode from starting.  However, the solution turned out to be simple:
we just installed all pending updates (in our case, they ended at version 1809), and the problem went away. We disabled
ICS, and it stayed disabled.

ICS can be enabled and disabled for individual network interfaces, but you'll need to disable it across your entire
system to free up port 53 for SubstratumNode.

To do so, press your Windows button and type Services. Scroll down to where you see "Internet Connection Sharing (ICS)"
in the left-hand column. Does the second column show it to be Running? If not, ICS isn't your problem, and you'll need
to look elsewhere.

If it is, then right-click on the Internet Connection Sharing item and choose Properties. Pull down the "Startup type"
list and choose "Disabled" so that it can't be restarted once it stops.  Now click the "Stop" button to kill the service.
You'll get a dialog box with a progress bar; the service should stop fairly quickly. After it does, click "OK" and
verify that the service list now shows the service as "Disabled" in the "Startup Type" column, with no value at all in
the "Status" column. If that's the case, you've successfully disabled ICS.

### Linux
We know of two reasonable solutions to the __Port 53 Problem__ in Linux: a complicated and annoying one that allows you to keep
using dns caching, and a much simpler and easier one that consists of disabling dns caching but will no longer allow you
to use intelligible names for the devices on your LAN.

#### Complicated And Annoying: Docker
This solution is too complex to detail here, but in broad strokes it involves running a Docker container that contains
a version of Linux that does _not_ have the __Port 53 Problem__, starting the SubstratumNode and a browser in that
container, and having the browser display its window on the X11 server running on your host machine.  We at Substratum
have used this solution in the past, and you can see how we've done it by looking in our 
[source code](https://github.com/SubstratumNetwork/SubstratumNode/tree/master/node/docker/linux_node). After installing
Docker on your machine, you may be able to put together a similar solution.

#### Simple But Incompatible: Disable DNS Caching

##### Ubuntu 18.04

Disable the service:

```
sudo systemctl disable systemd-resolved.service
sudo service systemd-resolved stop
```

Then edit `/etc/NetworkManager/NetworkManager.conf` and add the following line to the `[main]` section:

```
dns=default
```

Then remove the symlink.  `sudo rm /etc/resolv.conf`

Then restart the network manager (or reboot). `sudo service network-manager restart`

##### Ubuntu 16.04

If you have this problem, then on your machine there should be a file called `/etc/NetworkManager/NetworkManager.conf`.
To see if it's there, start a terminal window and type the following command:

`cat /etc/NetworkManager/NetworkManager.conf`

If you get an error message, this solution isn't for you; you'll need to try the __Complicated And Annoying__ solution or
ask for further help.

Otherwise, you should see a small configuration file with a line in it that looks like this:

`dns=dnsmasq`

If this line isn't in the file, this solution isn't for you; you'll need to try the __Complicated And Annoying__ solution or
ask for further help.

The thing to do is to modify this file. It's a protected system file, so you'll need administrative privilege to do so. On
most computers affected by this problem, you should be able to use `sudo` and type in your password to get administrative
privilege. (If you can't, show these instructions to your system administrator and have him follow them for you.)

If you're a Linux user, then you probably have a favorite text editor that you know how to use: `vi`, `vim`, `emacs`,
`gedit`, `atom`, `subl`, whatever. The important thing is not which text editor you choose, it's how you start it:

`sudo` \<your text editor\> `/etc/NetworkManager/NetworkManager.conf`

Once you've got the editor going, go to that line

```
dns=dnsmasq
```

and put a hash mark in front of it, then add another line below it:

```
#dns=dnsmasq
dns=default
```

Then save the file and exit.

Now, if you know how, restart your network manager. If you don't, reboot your machine--that'll do it. While you will no 
longer be able to refer to your LAN-connected devices by their names, you should now be able to start a SubstratumNode.

If you decide you'd rather run `dnsmasq` than SubstratumNode, or if you want to try the __Complicated And Annoying__
solution instead, just bring up that same file in your text editor again (don't forget the `sudo`), move the hash mark
from the `dns=dnsmasq` line to the `dns=default` line, so that it looks like this:

```
dns=dnsmasq
#dns=default
```

and restart your network manager (or reboot).
