# Blockchain Service URL

### What is a blockchain service URL?

A blockchain service url is a URL that MASQ Node uses to interact with various blockchains, either the Amoy and Ropsten
testnets or Polygon and Ethereum mainnets. On mainnets, MASQ uses the MASQ token; on testnets, it uses a test token.

#### MASQ Node software supports connections to the following blockchains:
**Ethereum**
- [x] Ropsten testnet
- [x] Ethereum mainnet

**Polygon**
- [x] Amoy testnet
- [x] Polygon mainnet *in beta testing*

To be fully functional MASQ Node needs communication to the blockchain for access to:
1. pay SHRD/MASQ to other Nodes for routing, blockchain, and exit services consumed, 
1. determine if other requesting Nodes have enough SHRD/MASQ to pay for services -- also ETH for gas fees, and 
1. discover payments from other Nodes for routing, blockchain, and exit services provided. This keeps your Node from 
   incorrectly banning other Nodes for not paying. 

There are two general types of Blockchain Services MASQ Node currently supports.

1. Connect with a remote service that provides a JSON RPC Ethereum client like [Infura.io](https://infura.io/) or [Alchemy.io](https://alchemyapi.io/) - these will require signing up for an account (most offer both free and premium accounts) but just providing an email address, which will allow you to generate an API key and an endpoint URL.
1. Run your own Ethereum miner such as a [Go Ethereum (geth)](https://geth.ethereum.org) or 
   [OpenEthereum](https://openethereum.github.io//) JSON RPC client locally on the same machine as 
   MASQ Node or on another machine within your private network.

### 1. Sign up for a free [Infura.io](https://infura.io/register) account.
Follow the instructions here [Infura.io/docs](https://infura.io/docs) to create a "Project"
Choose one of the following options for the network of your choice (if you are testing it is likely the Amoy testnet):

* Enter your Infura.io url `https://polygon-amoy.infura.io/v3/<YOUR-PROJECT-ID>` in the blockchain service url field of the GUI.
  
* For the `masq` command-line interface, use the `setup` command: 
  
    > `masq> setup --blockchain-service-url https://polygon-amoy.infura.io/v3/<YOUR-PROJECT-ID>`
  
* Edit your config.toml file and include the entry
  
    > `blockservice-service-url = "https://polygon-amoy.infura.io/v3/<YOUR-PROJECT-ID>"`

* Or define an environment variable
  
    * Windows
  
    > `set MASQ_BLOCKCHAIN_SERVICE_URL = https://polygon-amoy.infura.io/v3/<YOUR-PROJECT-ID>`
  
    * Linux or macOS
  
    > `export MASQ_BLOCKCHAIN_SERVICE_URL = https://polygon-amoy.infura.io/v3/<YOUR-PROJECT-ID>`

Change `<YOUR-PROJECT-ID>` with the PROJECT ID from your Infura.io Project Dashboard. Change the URL to 
mainnet when ready to spend and earn real MASQ. 

As soon as you begin consuming routing services from other MASQ Nodes, they will begin expecting you to pay them for
those services in SHRD or MASQ. If you live in a country where cryptocurrency like Ethereum or MASQ tokens are legal,
this isn't a problem: you can wait to start consuming routing services until after you have a wallet created, funded,
and configured, and you've set up your blockchain service account.

But if your country prohibits cryptocurrency transactions, you'll need your cryptocurrency-related transactions to be
protected by the MASQ Network. How can you set up your cryptocurrency environment using a network that requires
cryptocurrency to run?

Well, agility and quickness, that's how. The way the Accountant's delinquency bans work, a debtor is allowed to owe
a small amount of money for a fairly long time before he gets banned, or a large amount of money for only a short time
before he gets banned. (The precise times and amounts are configurable by the Noderunner, but the general shape of the
curve will be the same.) So the object is to start up your Node, activate your proxy or DNS subversion, and quickly and
smoothly arrange your blockchain service and fund your wallet so that A) your bills are small enough that B) your
Accountant can pay themq quickly enough that you don't get banned.

### 2. Do you feel up to the technical challenge of running a full Ethereum client, keep it running, and synchronized with the blockchain?

If so, run either `geth` or `parity` and let it sync the full Ethereum blockchain. 
You **do not** need to enable mining. Keeping it synchronized is sufficient. At this point CPU mining is 
not likely to earn any block rewards anyway, since GPU miners win all the rewards, having the vast majority 
of the hashing power.

Be aware that a fully synchronized blockchain can have considerable disk space requirements. On May 30, 2021, the
mainnet Ethereum blockchain was 240GB in size, which will take a long time to download even over a fast connection.
