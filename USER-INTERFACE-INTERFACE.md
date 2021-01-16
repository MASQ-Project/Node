# Communication Between `MASQNode` and User Interfaces

## Background

### Project Architecture

The `MASQNode` (or `MASQNode.exe` for Windows) binary is used for two different purposes. One is called the Daemon;
the other is called the Node.

The Node contains all the communications capabilities MASQ is known for. Its job is to start with root privilege,
open low ports, drop privilege to user level, and settle into sending and receiving CORES packages.

The Daemon is different. Its job is to start when the machine boots, with root privilege, and keep running with
root privilege until the machine shuts down. It is not allowed to communicate over the Internet, or with the Node.
This reduces the chance that an attacker's hack of the Node could gain root privilege on a user's machine.

Since the Daemon is always running, it listens on a `localhost`-only port (5333 by default) for connections
from user interfaces. UIs connect first to the Daemon on its well-known port. There are certain conversations that
the Daemon can carry on with the UI (one of which tells the Daemon to start up the Node), but when it's time, the
Daemon will tell the UI where the Node is so that the UI can connect directly to the Node.

If the Node crashes, the UI should reconnect to the Daemon. From there, if desired, it can direct the Daemon to
restart the Node.

Any number of UIs can connect to the Daemon and the Node. Information that is relevant only to one UI is sent only
to that UI; information that is relevant to all is broadcast. Currently there is no way for a UI to subscribe
only to those broadcasts in which it is interested; it will receive all broadcasts and has the responsibility to
ignore those it doesn't care about. If necessary, the subscription functionality can be added to the Node in the
future.

### Communications Architecture

#### Level 1

If the Daemon is started without specific settings, like this

```
$ ./MASQNode --initialization
```

it will try to come up listening for UI connections on port 5333. But if it's started like this

```
$ ./MASQNode --initialization --ui-port 12345
```

it will try to come up listening for UI connections on port 12345. If it finds the target port already occupied, it
will fail to start.

The Node is started by the Daemon. When the Daemon starts the Node, it will choose an unused port and direct the
Node to listen for UIs on that port. When the Daemon redirects a UI to the Node, it will supply in the redirect
message the port on which the Node is running.

The Daemon and the Node listen for UIs only on the `localhost` pseudo-NIC. This means that all the UIs for a particular
Daemon or Node must run on the same computer as the Daemon or Node: they cannot call in over the network from another
machine. This restriction is in place for security reasons.

#### Level 2

The link between the UIs and the Daemon or Node is insecure WebSockets, using the protocol name of `MASQNode-UIv2`.
Any other protocol name will be rejected, and no connection will be made.

#### Level 3

Once the WebSockets connection is established, all the messages passed back and forth between the UIs and the Daemon
or Node are formatted in JSON. A message packet is always a JSON object, never a scalar or an array.

#### Level 4

The low-level JSON format of `MASQNode-UIv2` messages is reasonably simple. It looks like this:

```
{
    "opcode": <string>,
    "contextId": <positive integer>,
    "payload": <optional object>,
    "error": <optional object>
}
```

The `opcode` is a short string that identifies the message type. Sometimes the same opcode will be used for two
different message types if they can easily be distinguished by some other context--for example if one type is
only ever sent from the UI to the Node, and the other type is only ever sent from the Node to the UI.

The `contextId` is a positive integer best thought of as a conversation number. Just as there can be many UIs 
connected to the same Node, each UI can be carrying on many simultaneous conversations with the Node. When a 
request is sent as part of a unique conversation, the Daemon and the Node guarantee that the next message 
received in that conversation will be the response to that request. It is the responsibility of each UI to 
manage `contextId`s. When the UI wants to start a new conversation, it merely mentions a new `contextId` in 
the first message of that conversation; when it's done with a conversation, it just stops mentioning that 
conversation's `contextId`.

It may be tempting to use a single `contextId` for all the messages a UI sends in its lifetime, and this is
perfectly legal as far as the Node and Daemon are concerned; but if the UI does this, it will have to determine
for itself which conversation each incoming message is part of. For example, if there are three conversations
going on at once, this might happen:

1. → Request for conversation 1
1. → Request for conversation 2
1. ← Response for conversation 1
1. → Request for conversation 3
1. ← Broadcast from Node
1. ← Response for conversation 3
1. ← Response for conversation 2

If each conversation has its own ID, it'll be a lot easier to tell what's going on when a message arrives
than it will be if every message is part of conversation 555.

Some messages are always isolated, and never part of any conversation, like the Broadcast in step 5 above. 
These messages will be identifiable by their `opcode`, and their `contextId` should be ignored. (In the 
real world, it's always zero, but depending on that might be dangerous.)

Neither the Daemon nor the Node will ever start a conversation, although they will send isolated, non-conversational
messages.

The `payload` is the body of the message, with its structure being signaled by the contents of the `opcode` field.
See the Message Reference section below for specifics about the `payload` field for each type of message.
It will be present if and only if the `error` field is not present.

The object in the `error` field, if present, tells about the error that was encountered in the process of trying to
satisfy a request. It will be present if and only if the `payload` field is not present. It will have this structure:

```
{
    code: <nonnegative integer>,
    message: <string>
}
```

The `code` field is a 64-bit integer. Its numeric value is not particularly important, but it denotes a kind of
error. The UI can tell whether a particular operation is producing the same kind of error repeatedly, or different
kinds of errors, by comparing one `code` to the next.

The `message` field is a string with a hopefully-friendly description of the error.

There is no provision in the `MASQNode-UIv2` protocol for UIs to communicate with one another. A UI may be able
to deduce, from broadcasts, the existence of other UIs, but it can never be assured that there _aren't_ any other UIs
connected to the Node or Daemon.

#### Level 5

The structure of the `payload` of a `MASQNode-UIv2` message depends on the `opcode` of that message. See the
Message Reference section below.

## General Operational Concepts

### Daemon

#### Setup

The Node requires quite a bit of configuration information before it can start up properly. There are several
possible sources of this configuration information. The primary source, though, is the command line that's used
to start the Node. There are many parameters that can be specified on that command line, and the Daemon needs to
know them all in order to start the Node.

Accumulating this information is the purpose of the Daemon's Setup functionality, which is a large proportion of
what it does.

The Daemon has a space inside it to hold Setup information for the Node. A UI can query the Daemon to get a dump
of the information in the Setup space. When the Node is not running, the information in the Setup space can be
changed by the UI. When the Node is running, the information in the Setup space is frozen and immutable. This is
so that when the Node is running, you can use the UI to query the Daemon to discover the configuration with which
the Node was started.

If a Node is shut down, a new Node can easily be started with exactly the same configuration as its predecessor
as long as the information in the Setup space is not disturbed.

#### Start

When the Start operation is triggered, the Daemon will try to start the Node with the information in the Setup
space. The response message will tell whether the attempt succeeded or failed. 

#### Redirect

As long as the UI sends the Daemon messages that the Daemon understands, the Daemon will respond appropriately to
them. But if the UI sends the Daemon a message the Daemon doesn't understand, the Redirect operation may come
into play.

If the Node is not running, there's nowhere to Redirect, so the Daemon will just send back an error response.

However, if the Node _is_ running, the Daemon will send back a Redirect response, which will contain both
information about where the Node is running and also the unexpected message sent to the Daemon. When the UI
gets a Redirect, it should drop the WebSockets connection to the Daemon, make a WebSockets connection to the
Node on the port supplied in the Redirect message (on `localhost`, using the `MASQNode-UIv2` protocol), and
resend the original message--which, in case the UI doesn't remember it anymore, is helpfully included in the
Redirect payload.  If it's a valid Node message, the Node should respond appropriately to it.

### Node

#### Database password

The Node stores its configuration information in a database. A UI should certainly never attempt to write to
this database, but it also shouldn't attempt to read from it, for two reasons: first, some of the information
in the database is encrypted because it's sensitive; and second, the Node does some caching work for performance
reasons, so what a UI finds in the database might be several minutes or more old. The UI should ask the Node
directly for the information it needs.

The information in the database that's encrypted needs a password to decrypt it. When the Node is first installed,
there is no secret information in the database; therefore, the database has no password. A password can be set 
on the database without storing any secrets in it, if desired, but in order to store secrets, a password _must_
be set on the database.

The password is never stored anywhere but in memory by the Node; it should not be persisted anywhere by a UI
either. In order to carry out certain instructions, the Node will need the password from the UI, which means the
UI will need to get it from the user.

Using `MASQNode-UIv2` messages, the UI can check to see if a password is correct; it can change the database
password (if it knows the old one); and it can be notified when some other UI changes the password (so that it
knows the one it's aware of is no longer valid).

#### Configuration

The configuration information with which the Node runs (which is different from the setup information with
which the Daemon starts a Node) is available via `MASQNode-UIv2` as well. A UI can request the configuration
information, and if the information changes for some reason, all UIs will be notified so that--if desired--they
can request the latest version.

#### Shutdown

The Shutdown operation causes the Node to cease operations and terminate. The UI will receive a response, and then
the WebSockets connection will be dropped by the Node.

Whenever the WebSockets connection is dropped, whether the Shutdown operation is in progress or not, the UI should
reconnect to the Daemon.

If for some reason the WebSockets connection is _not_ dropped by the Node within a few milliseconds of the response
to the Shutdown message, that indicates that the Node has somehow become hung on the way down. In this case, the
WebSockets connection to the Node will probably be of no further use. The UI may choose to inform the user that
bad things are happening which will probably require user intervention.

## Message Reference

The following messages are listed in alphabetical order by opcode. If several messages have the same opcode,
they'll be ordered under that opcode with the request first and the response later. The `opcode` and `contextId`
fields are not included in the message layouts, but they must be provided by the UI and will be specified
by the Daemon or Node.

The various errors that can result from each request are not specifically mentioned unless they indicate a
condition the UI can correct.

#### `changePassword`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "oldPasswordOpt": <optional string>,
    "newPassword": <string>,
}
```
##### Description:
This message is used to change the database password, provided the UI knows the existing password or is
correctly aware of the fact that there is no existing password.

If the database currently has no password, omit the `oldPasswordOpt` field. If there's already a database
password, there is no way to remove it, even if the database does not yet contain secrets.

#### `changePassword`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
}
```
##### Description:
If the password was successfully changed, this is a simple acknowledgment that the change is complete.

#### `checkPassword`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPasswordOpt": <string>
}
```
##### Description:
This message is used to check whether a password the UI knows is actually the real database
password.

Note that under some circumstances, during the first few minutes after installation, a new MASQNode
may not have any database password at all.

There's no way to make the Node tell you what the database password is, but if you have an idea
what it might be, you can check your idea by sending this message with your idea in the
`dbPasswordOpt` field. If you're checking to see whether there's no password, omit this
field.

#### `checkPassword`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "matches": <boolean>
}
```
##### Description:
If you send a `checkPassword` request to the Node, it will respond with this message. If the
password you proposed (or the absence-of-password you proposed) matched the database password,
the `matches` field will be `true`; otherwise it will be `false`.

If there was an error checking the password, you'll get a standard error response with a 64-bit
code, where the high-order eight bits are 0x01.

#### `configuration`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPasswordOpt": <optional string>
}
```
##### Description:
NOTE: This message is planned, but not yet implemented.

This message requests a dump of the Node's current configuration information. If you know the database password,
provide it, and the response will contain the secrets in the database. If you don't supply a password, or you
do but it's wrong, you'll still get a response, but it will have only public information: the secrets will be
missing.

Another reason the secrets might be missing is that there are not yet any secrets in the database.

#### `configuration`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "currentSchemaVersion": <string>,
    "clandestinePort": <string>,
    "gasPrice": <number>,
    "mnemonicSeedOpt": <optional string>,
    "consumingWalletDerivationPathOpt": <optional string>,
    "earningWalletAddressOpt": <optional string>,
    "pastNeighbors": [
        <string>,
        <string>, ...
    ],
    "startBlock": <number>
}
```
##### Description:
NOTE: This message is planned, but not yet implemented.

This conveys the Node's current configuration information. Some of it is optional: if it's missing, it might be
because it hasn't been configured yet, or it might be because it's secret and you didn't provide the correct
database password. If you want to know whether the password you have is the correct one, try the
`checkPassword` message.

* `currentSchemaVersion`: This will be a three-part version number for the database schema. This will always
be the same for a given version of Node. If you upgrade your Node, and the new Node wants to see a later
schema version in the database, it will migrate your existing data to the new schema and update its schema
version. If this attempt fails for some reason, this value can be used to diagnose the issue.

* `clandestinePort`: The port on which the Node is currently listening for connections from other Nodes.

* `gasPrice`: The Node will not pay more than this number of Gwei for gas to complete a transaction.

* `mnemonicSeedOpt`: This is a secret string of hexadecimal digits that corresponds exactly with the mnemonic
phrase, plus any "25th word" mnemonic passphrase. You won't see this if the password isn't correct. You also
won't see it if the password is correct but the seed hasn't been set yet.

* `consumingWalletDerivationPathOpt`: This is the derivation path (from the mnemonic seed) of the consuming wallet.
More than likely, it's m/44'/60'/0'/0/0.
  
* `earningWalletAddressOpt`: The wallet address for the earning wallet. This is not secret, so
if you don't get this field, it's because it hasn't been set yet.

* `pastNeighbors`: This is an array containing the Node descriptors of the neighbors the Node is planning to
try to connect to when it starts up next time.

* `startBlock`: When the Node scans for incoming payments, it can't scan the whole blockchain: that would take
much too long. So instead, it scans starting from wherever it left off last time. This block number is where
it left off last time.

#### `configurationChanged`
##### Direction: Broadcast
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
NOTE: This message is planned, but not yet implemented.

If you receive this broadcast message, then something about the Node's configuration has changed. If you're
interested, you can send a `configuration` request and get the new info; or you can just ignore this message
if you don't care. If you're caching the configuration information, this would be a good time to invalidate
your cache.

#### `crash`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "actor": <string>
    "panicMessage": <string>
}
```
##### Description:
This is a message used only for testing. It will be unrecognized unless the Node that receives it has been
started with the `--crash-point message` parameter. It's used to test the behavior of the Node during a crash
and the reactions of the software around it to that crash.

It makes the Node panic and crash at a specified time that can be chosen by the tester. The normal rule for the
Node is that it's not allowed to crash because of anything it receives over the network from the outside; this
message is an exception to that rule, which is why it must be enabled by a special parameter.

The `actor` field in the payload is the name of the actor (Node subsystem) that will be forced to crash by the
message. As of this writing, the only valid value is "BlockchainBridge".

The `panicMessage` field in the payload is the message that will be passed to the `panic!()` macro by the Node
immediately upon receiving the message.

#### `crash`
##### Direction: Broadcast
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "processId": <integer>,
    "crashReason": {
        <key>: <string>
    }
}
```
##### Description:
When the Node has been running, and the Daemon senses that it is no longer running, the Daemon will broadcast a
`crash` message to all UIs connected to the Daemon. This doesn't necessarily mean the Node has experienced
catastrophic failure: it may have been instructed by a UI to shut down.

The `processId` field contains the platform-dependent process ID of the late Node.

The `crashReason` field is rather clumsy, and there's a card (GH-323) in the backlog to improve it. At the moment,
it's an object with one field, which may be named "ChildWaitFailure", "NoInformation", or "Unrecognized". If the
field is named "ChildWaitFailure" or "Unrecognized", the value is a string with additional information. If the key
is "NoInformation", the value is `null`.

#### `descriptor`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
Requests the Node descriptor from a Node.

#### `descriptor`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "nodeDescriptor": <string>
}
```
##### Description:
Contains a Node's Node descriptor.

#### `financials`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "payableMinimumAmount" = <nonnegative integer>,
    "payableMaximumAge" = <nonnegative integer>,
    "receivableMinimumAmount" = <nonnegative integer>,
    "receivableMaximumAge" = <nonnegative integer>
}
```
##### Description:
Requests a financial report from the Node.

In most cases, there will be many records in the database, most of them irrelevant because of amount or age.
Therefore, when the UI requests a financial report, it should specify minimum amounts and maximum ages. Records
with amounts smaller than the minimums, or older than the maximums, won't be included in the results, although
their values will be included in the totals.

This request will result in a cluster of queries to the database, which are quick but not instantaneous,
especially on old databases that contain lots of records. A UI that makes this request too many times per
second will perceptibly degrade the performance of the Node.

Amounts are specified in gwei (billions of wei); ages are specified in seconds. Values less than zero or
greater than 64 bits long will cause undefined behavior.

#### `financials`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "payables": [
        {
            "wallet": <string>,
            "age": <nonnegative integer>,
            "amount": <nonnegative integer>,
            "pendingTransaction": <optional string>
        },
        < ... >
    ],
    "totalPayable": <nonnegative integer>,
    "receivables": [
        {
            "wallet": <string>,
            "age": <nonnegative integer>,
            "amount": <nonnegative integer>
        },
        < ... >
    ],
    "totalReceivable": <nonnegative integer>
}
```
##### Description:
Contains a financial report from the Node.

In most cases, there will be accounts in the database that are too old, or whose balances are too low, to
show up in this report. The `totalPayable` and `totalReceivable` fields will be accurate, but they will
probably be larger than the sums of the `payables` and `receivables` `amount` fields. The UI may choose to
ignore this discrepancy, or it may generate an "Other" account in each case to make up the difference.

The `wallet` fields will consist of 40 hexadecimal digits, prefixed by "0x".

The `age` fields contain the age in seconds, at the time the request was received, of the most recent transaction
on the associated account. The value will not be less than zero or longer than 64 bits.

The `amount` fields contain the total amount in gwei owed to or due from the associated account at the time the
request was received. The value will not be less than zero or longer than 64 bits.

The `pendingTransaction` fields, if present, indicate that an obligation has been paid, but the payment is not
yet confirmed on the blockchain. If they appear, they will be standard 64-digit hexadecimal transaction numbers,
prefixed by "0x". If no `pendingTransaction` is given, then there were no pending payments on that account
at the time the request was received.

The `payables` and `receivables` arrays are not in any particular order.

For security reasons, the Node does not keep track of individual blockchain transactions, with the exception
of payments that have not yet been confirmed. Only cumulative account balances are retained.

#### `generateWallets`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "dbPassword": <string>,
    "mnemonicPhraseSize": <number>,
    "mnemonicPhraseLanguage": <string>,
    "mnemonicPassphraseOpt": <optional string>,
    "consumingDerivationPath": <string>,
    "earningDerivationPath": <string>
}
```
##### Description:
This message directs the Node to generate a pair of wallets and report their mnemonic phrase and their addresses
back to the UI. If the database already contains a wallet pair, the wallet generation will fail.

`dbPassword` is the current database password. If this is incorrect, the wallet generation will fail.

`mnemonicPhraseSize` is the number of words that should be generated in the mnemonic phrase. The acceptable values
are 12, 15, 18, 21, and 24. It's recommended that UIs default to 24-word phrases and require the user to specifically
demand a lower value, if desired.

`mnemonicPhraseLanguage` is the language in which the mnemonic phrase should be generated. Acceptable values are
"English", "Chinese", "Traditional Chinese", "French", "Italian", "Japanese", "Korean", and "Spanish".

`mnemonicPassphraseOpt`, if specified, is the "25th word" in the mnemonic passphrase: that is, an additional word
(it can be any word; it's not constrained to the official mnemonic-phrase list) that will be used along with the
24 standard words to generate the seed number from which the wallet keys are derived. If this value is supplied,
then the user will have to specify it as well as the 24 standard words in order to recover the wallet pair. Note
that neither the 24 standard words nor this value is persisted anywhere: it's up to the user to keep track of them.

`consumingDerivationPath` is the derivation path from the generated seed number to be used to generate the consuming
wallet. By convention, it is "m/44'/60'/0'/0/0", but in this message it is required and no defaulting is performed
by the Node.

`earningDerivationPath` is the derivation path from the generated seed number to be used to generate the earning
wallet. By convention, it is "m/44'/60'/0'/0/1", but in this message it is required and no defaulting is performed
by the Node.

If the user wants to consume from and earn into the same wallet, he should provide the same derivation path for both.

#### `generateWallets`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "mnemonicPhrase": [
        <string>,
        <string>,
        [...]
    ],
    "consumingWalletAddress": <string>,
    "earningWalletAddress": <string>
}
```
##### Description:
This message describes the pair of wallets that has been generated and configured on the Node.

`mnemonicPhrase` is the list of 24 (or 12 or 15 or 18 or 21) words that, when combined with the mnemonic passphrase,
if specified, will produce the seed from which the consuming and earning wallets are derived. They are rendered in
the requested language, including non-ASCII Unicode characters encoded in UTF-8 where appropriate.

`consumingWalletAddress` is the address of the generated consuming wallet.

`earningWalletAddress` is the address of the generated earning wallet.

#### `newPassword`
##### Direction: Broadcast
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
No data comes with this message; it's merely used to inform a UI that the database password has changed.
If the UI is remembering the database password, it should forget it when this message is received.

#### `redirect`
##### Direction: Unsolicited Response
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "port": <positive integer>,
    "opcode": <string>,
    "contextId": <optional positive integer>,
    "payload": <string>,
}
```
##### Description:
This message will be sent by the Daemon to a UI in response to a message with an opcode the Daemon doesn't
recognize, when the Node is running. The Daemon's assumption is that such a message must be meant for the Node.

The `port` field contains the port number on which the Node is listening for UI connections.

The `opcode` field contains the opcode of the unrecognized message.

The `contextId` field, if present, contains the `contextId` of the unrecognized message. If not present, then
the unrecognized message was not part of a conversation.

The `payload` field is a string of JSON, containing the payload of the unrecognized message.

The UI should disconnect from the Daemon, connect to the Node on `localhost` at the indicated port,
reconstruct the original message from the `opcode`, `contextId`, and `payload` fields, and send it to the
Node.

#### `setup`
##### Direction: Request
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "values": [
        {
            "name": <string, see below>,
            "value": <optional string>
        },
        < ... >
    ]
}
```
##### Description:
Requests modifications to the Daemon's Setup space and a dump of the results.

The `values` array may be empty. If it is, no modifications will be made, but a report of the existing contents
of the Setup space will be returned.

The `name` field is one of a set of known parameter names whose value should be changed. See below for a list.

The `value` field, if present, holds the new value for the parameter. If not present, the parameter value will
be cleared.

###### Permitted `name`s
* `blockchain-service-url` - URL of the blockchain service to use: currently only Infura is supported.
* `chain` - `mainnet` or `ropsten`. The blockchain the Node should connect to. 
* `clandestine-port` - The port at which other Nodes will contact this one.
* `config-file` - Path to or name of the TOML file from which to take additional configuration.
* `consuming-private-key` - 64-digit hexadecimal number containing the consuming wallet's private key.
* `data-directory` - Path to data directory.
* `db-password` - Password to unlock the sensitive values in the database.
* `dns-servers` - Comma-separated list of DNS servers to use.
* `earning-wallet` - Wallet into which earnings should be deposited.
* `gas-price` - Transaction fee to offer on the blockchain.
* `ip` - The public IP address of the Node.
* `log-level` - The lowest level of logs that should be recorded. `off`, `error`, `warn`, `info`, `debug`, `trace`
* `neighborhood-mode` - `zero-hop`, `originate-only`, `consume-only`, `standard`
* `neighbors` - Comma-separated list of Node descriptors for neighbors to contact on startup
* `real-user` - Non-Windows platforms only, only where required: <uid>:<gid>:<home directory>

#### `setup`
##### Direction: Response or Broadcast
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "running": <boolean>,
    "values": [
        {
            "name": <string>,
            "value": <string>,
            "status": <string, see below>,
        },
        < ... >
    ],
    "errors": [
        [<string, see below>, <string, see below>],
        < ... >
    ]
}
```
##### Description:
Conveys the contents of the Daemon's Setup space. A UI will receive this message as a response (with a
meaningful `contextId`) if it sends a `setup` request; but it will also receive this message as an unsolicited
broadcast if another UI sends a `setup` request that results in actual changes to the Daemon's Setup space.

The `running` field will be true if the Node is currently running, or false otherwise. If true, the proposed
changes, if any, in the request that stimulated this response or broadcast were ignored, because the Setup
space is immutable while the Node is running.

The `values` array contains a list of the values in the Setup space. For each object in the list:

The `name` field is the name of the parameter, one of the names listed for the request above.

The `value` field is the value of that parameter. If the parameter has no value, the `value` field will be
a blank string.

The `status` field has one of the following values:
* `Default` - The parameter has a default value, and has not been changed from it.
* `Configured` - The parameter has taken its value from a configuration file or an environment variable.
* `Set` - The parameter was set by a UI using a `setup` message.
* `Blank` - The parameter has no value, and no value is required.
* `Required` - The parameter has no value, but some value is required to start the Node.

Sometimes, the values in the Setup space may be incomplete, inconsistent, or obviously incorrect. When this
happens, the `errors` array will be populated with error messages about the problem parameters. It's an array
of two-element arrays; each two-element array will have the name of the offending parameter first, and an
appropriate error message second. If there are no detectable errors, the `errors` array will be empty.

The presence of errors or `Required` parameters will not prevent the Daemon from attempting to start the Node,
but it will prevent the Node from starting or running properly. The UI may choose not to offer the user the
option to start the Node until the Daemon is happy, but that's optional.

#### `shutdown`
##### Direction: Request or Response
##### Correspondent: Node
##### Layout:
```
"payload": {}
```
##### Description:
The `shutdown` message has an empty payload. As a Request, it instructs the Node to shut down. As a Response, it
notifies the UI that the Node is almost shut down. (Obviously, the Node can't send a Response if it's _completely_
shut down.)

#### `start`
##### Direction: Request
##### Correspondent: Daemon
##### Layout:
```
"payload": {}
```
##### Description:
The `start` message has an empty payload. It causes the Daemon to try to start the Node with whatever configuration
information is presently in its Setup space.

#### `start`
##### Direction: Response
##### Correspondent: Daemon
##### Layout:
```
"payload": {
    "newProcessId": <integer>,
    "nodeDescriptor": <string>,
    "redirectUiPort": <integer greater than 1024>,
}
```
##### Description:
If a `start` attempt is successful, this response will arrive.

The `newProcessId` field is the system-dependent process ID of the newly-running Node.

The `redirectUiPort` field is the WebSockets port on which the UI can now connect to the Node. The UI that actually
starts the Node can take advantage of this to preemptively connect to the Node without processing a Redirect; but
a UI that starts after the Node is already running must go through the Redirect operation to find it. It requires
less code to simply have your UI always use Redirects.

Because the Daemon is not allowed to communicate with the Node for security reasons, the Daemon cannot know
the Node's Node descriptor; therefore it cannot be included in the response to the `start` request. To
discover a newly-started Node's Node descriptor, send the `descriptor` message directly to the Node itself.

#### `unmarshalError`
##### Direction: Response
##### Correspondent: Daemon or Node
##### Layout:
```
"payload": {
    "message": <string>,
    "badData": <string>,
}
```
##### Description:
If the Daemon or the Node can't unmarshal a message from a UI, it will send this message in response.

The `message` field describes what's wrong with the unmarshallable message.

The `badData` field contains the unmarshallable message itself.
