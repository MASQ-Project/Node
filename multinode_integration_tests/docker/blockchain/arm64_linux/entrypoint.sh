#!/bin/sh

# All ordinal wallets begin with zero balances. Except the contract owner wallet as the only one populated with usable
# means. The means are meant to be redistributed from here to any accounts that will need it. Notice the argument
# --account '<contract owner wallet private key>,<ETH in wei>' that assigns a certain initial balance.
#
# This same principle of wallets fed from this centric wallet at the test setup is followed by both the gas currency
# and the MASQ tokens. With those, there is practically no other option for their strong dependency on the blockchain
# smart contract that defines the entire supply is deployed to the contract owner's wallet.

ganache-cli \
  -h 0.0.0.0 \
  -p 18545 \
  --networkId 2 \
  --verbose \
  -m "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term toddler sphere ripple idle dragon curious hold" \
  --defaultBalanceEther 0 \
  --account '0xd4670b314ecb5e6b44b7fbe625ed746522c906316e66df31be64194ee6189188,10000000000000000000000'
