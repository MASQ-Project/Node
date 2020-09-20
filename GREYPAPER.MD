# MASQ

## Project Greypaper

# TABLE OF CONTENTS

| Topic | Page # |
| ------ | ------ |
| Preamble – The Greypaper | [Navigate](#preamble) |
| Introduction | [Navigate](#introduction) |
| Solution – Rule of Three | [Navigate](#solution) |
| Founding Principles | [Navigate](#founding-principles) |
| Key Goals Currently | [Navigate](#key-goals) |
| Docker Style CLI | [In progress](#docker-cli) |
| Graphic User Interface (GUI) | [In progress](#gui) |
| Clandestine Routing | [In progress](#clandestine) |
| Tokenomics | [Navigate](#tokenomics)  |
| Don the MASQ & Get Involved | [Support Us](#support-us) |
| SUPPORT OUR CAUSE | [Donate](#donate) |
| References | [References](#references) |

<a id="preamble"></a>
# PREAMBLE THE GREYPAPER

Readers may be thinking “Why is this document is called a ‘Greypaper’, and not a Whitepaper?

The Committee’s combined years of experience in business, technology, cryptocurrency and project management yielded an interesting idea - one of the MASQ Committee decided that there had to be an alternative to the mainstream idea of releasing a Whitepaper.

Whitepapers are exactly what they sound like – written in black and white and often outlining definitive goals and deadlines.

This Greypaper will be a living and evolving document that can be updated on a needs-basis with accurate information. All the while providing enough starting information for readers to appreciate the general vision and purpose of the project.

Through this, MASQ aspires to not only be transparent in their goals and intentions, but also to avoid hype, disappointment and misinformation.
 
# INTRODUCTION

MASQ is a community-driven project aimed at solving the problem of internet censorship by repressive regimes. The project Committee is addressing this by building a decentralized mesh network which happens to also be censorship resistant.

By doing so, it will allow content available on the World Wide Web to be accessible to anyone and everyone with an internet connection, all while allowing users to both share internet freedom and have an incentive to dedicate their excess bandwidth to the network.

**MASQ intends to deliver an Open Source solution to a growing Real World set of issues through a unique approach combining:**
- Programming
- Blockchain application
- Network encryption
- Software design
- Self-healing autonomous network structures

MASQ’s vision is that its use can attract over 1 million users across millions of devices and create an ecosystem of applications that leverages the decentralized mesh network.


> “A whole world behind the MASQ”

<a id="solution"></a> 
# SOLUTION – POWER OF THREE

The software solution is made up of three design components: 

 - Encrypted - Completed - Node allows--and encourages--encrypted connections, but it mainly addresses operations on a lower level. It operates on standard protocols such as TLS, SSL and HTTP/S 

 - Untraceable - Completed - Data is sent through a multi-hop network route that changes too quickly to trace
 
<a id="clandestine"></a>
 - Clandestine – **In progress** - Will hide not only the data, not only the route, but also the very fact that the user is using MASQ at all
 
Read more about these methods in detail on the [Encryption Wiki Page]

 
# FOUNDING PRINCIPLES
 
## Decentralized Governance
The MASQ Committee intends to have a core group of individuals forming a committee. At an agreed point, the Committee will dissolve, allowing the Open Source project to be fully decentralized.

There will be no CEO, and practical methods will be applied to ensure no one person controls the entire project.

## Community Spirit
The MASQ Committee have all been born of other projects and communities - they understand that without the true spirit of ‘By the Community, for the Community” the network and thus the project will cease to exist. From these humble roots, the Committee want to actively grow the Community and realize the full potential that the project can bring to the modern world of internet communication.

## Privacy
MASQ intends to keep user privacy as an utmost priority, as without true privacy of the network participants, the network cannot grow to its full potential across the world to restricted countries, where access to such a solution could come with severe penalty from Government and watchdog agencies.

Similarly, members of the Committee will remain pseudo-anonymous until such time that the network will be completely immutable, and there is little to no external threat to them. Some of the Committee are willing to be openly identified.
 
<a id="key-goals"></a>
# PROJECT MILESTONES

<a id="docker-cli"></a>
### Docker-Style CLI Interface - in progress, nearing completion
We have discontinued development and maintenance on the dated GUI, which was not only inefficient, but didn't reflect the features of Node entirely. From here our development is focused on the skeleton behind any GUI, and is now based on a Command Line interface, which will be adapted to be used on the main platforms.

Our goal is to have a configuration file be set up and referenced by the software Daemon, and then Node can be initialized by the user with a few simple commands on a Command Prompt in Windows, Linux or Mac

After more of our UI-Gateway design is developed and implemented, further UI components and GUIs can be designed and built on top for more user-friendly adoption and full-fledged visual features.

As of August 2020, most of the UI-Gateway interface has been implemented and allows UIs to communicate directly with the running Node instance (masqd).

<a id="gui"></a>
### Graphic User Interface (GUI) - in progress
Through our amazing Community, we have formed a group who is developing a streamlined GUI that will operate my communicating through the new MASQ Node UI-Gateway over Websocket broadcasts and messaging.

The GUI will first be a browser-based solution for Alpha and Beta type testing with community, and then be developed into further iterations of GUIs. These may be based on other platforms or languages for greater user experience and streamlined features.

### Additional Key Milestones

* Auto Port-Forwarding

* Clandestine Routing

* Neighborhood Modes

* Terminal Intelligence


## MASQ Project GitHub is Open Source
The MASQ [GitHub] is an Open Source fork of Substratum (the code base was created and developed by Substratum LLC, a registered US company based in Tennessee) – under the GPLv3 license. All the forked source code used from the latest repo of Substratum is cited as such and credit given properly.

Starting repositories include forks of:
* [SubNode]
* [SubTNT]

<a id="tokenomics"></a>
# Tokenomics

>Our true goal is simply development!

The MASQ ERC20 token will be a pure utility token. Its primary purpose is to provide a monetization component within the Node software to allow micro-transactions between nodes providing services to each-other within the network. These services are measured and values are individually set by the user of each Node, creating a 'free and open market' within the network itself for users to provide their bandwidth and Node routing services.

This monetization component is inherent to the security of the network, as it ensures:
- that users can both exchange a token to prove they are a reliable consumer or server of services
- reduce the likelihood of large scale network attacks such as botnets and DDoS
- 'Bad actor' Nodes or Nodes not clearing their consuming token debt will be banned or marked in a delinquent list, thus rendering them inactive Nodes

## Smart Contract
MASQ is using a clone of an OpenZeppelin ERC20 token smart contract adapted by Substratum (GitHub repo [sub-contract]), which was audited by Quantstamp in 2018-2019. It was modified with a single constructor to prevent protection from double-spending attacks.

Our smart contract in Solidity can be view publicly on our [verified contract address](https://etherscan.io/address/0x02ba9B528425f9de08F961B88A10b03Be8B8B998) on etherscan.io

## Token Supply 
Final Total Supply is 236,424,274.7575735
This is 50% of the original minted supply from the deployed Smart Contract

## Development Wallet
A development wallet of 40 million tokens is allocated, to be distributed at the discretion of the Committee following approval. Distribution is primarily for network-scaling, liquidity providers and business development as long as the market supports it. All distributions will be well communicated before any releases of this allocation.

## Committee Wallets
A Committee wallet has 9 million tokens allocated for members
*(currently there are 6 permanent members)*

## Airdrop Distribution (completed on Feb 22, 2020)
All non-exchange wallets **holding 500 or more SUB tokens** were airdropped MASQ tokens on a 1:1 ratio

Major exchange wallets and previous project founders/network wallets were excluded from airdrop. 

Using blockchain analysis tools, the MASQ committee reviewed monthly historical snapshots of holders from Dec 2019, Jan 2020 and Feb 2020. There were not significant changes to token-holder balances in this time.

Final snapshot was taken at 3:50pm 6th Feb 2020 PST, which coincides with the Committee announcement of the plans to airdrop the custom MASQ token. This was to avoid both manipulation and speculative trading of other tokens.

## Tokens Supply Adjustment (completed on May 11, 2020)
Unallocated tokens (235,575,725.2424265) have been sent to the zero-ethereum address - this occured on 11th May 2020 and the Transaction Hash can be viewed [here](https://etherscan.io/tx/0x9401af799b5aca513081e3541b6a15f6d2de84bd44c982ba1e7feea050f6bf5f) on etherscan.io

## Suspense - remaining tokens
There are 9.7 million tokens that were estimated for previous token holders on the COSS exchange. This was before their platform underwent a corporate changeover and discussions stalled in terms of partnership to support holders. Options are still being explored, but these tokens will be repurposed once no appropriate arrangement can be reached between management.


<a id="support-us"></a>
# GET INVOLVED

>Do you have a passion for Freedom? Freedom of Information for the world?
>Do you have knowledge of Rust, or similar programming and would like to volunteer some of your time?
>Have you simply wanted and try to test a superior alternative to VPN or Tor?

**Join our Community and Contact us!**

Get in Touch
 - [Telegram]
 - [Twitter]
 - [GitHub]
 - [Website]

<a id="donate"></a>
# SUPPORT OUR CAUSE

As all of our Committee are volunteers donating our time and efforts, we will rely on donations from our community to help fund airdrop services, gas fees and other related costs.

ETH address for any donations from our wonderful community:

[0x27d9A2AC83b493f88ce9B4532EDcf74e95B9788d](https://etherdonation.com/d?to=0x27d9A2AC83b493f88ce9B4532EDcf74e95B9788d&amount=0.02)

BTC - ```bc1qnsm0eqt9z9228n7hqc6a0g9dns84vsg3whnmsh```
 
<a id="references"></a>
## REFERENCES

**Substratum Sources and Links:**
- [GNU GPLv3 License](https://github.com/SubstratumNetwork/SubstratumNode/blob/master/LICENSE)
- [SubNode Repo](https://github.com/SubstratumNetwork/SubstratumNode)
- [SubTNT Repo](https://github.com/SubstratumNetwork/TNT)

**OpenZeppelin Token Contracts:**
- [MIT License](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/LICENSE)
- [Contract Library](https://github.com/OpenZeppelin/openzeppelin-contracts)
- [ERC20 Tokens](https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/token/ERC20)


[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job)

   [SubNode]: <https://github.com/SubstratumNetwork/SubstratumNode>
   [SubTNT]: <https://github.com/SubstratumNetwork/TNT>
   [sub-contract]: <https://github.com/SubstratumNetwork/sub-contract>
   [Telegram]: <https://t.me/MASQ_ai>
   [Twitter]: <https://twitter.com/MASQ_ai>
   [GitHub]: <https://github.com/MASQ-Project>
   [Website]: <https://MASQ.ai>
   [Encryption Wiki Page]: https://github.com/MASQ-Project/Node/wiki/Encryption-Methods-Explained
