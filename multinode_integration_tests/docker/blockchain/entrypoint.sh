#!/bin/sh

# All ordinal wallets begin with a zero balance,
# except the contract owner wallet whose initial gas balance is supposed to be redistributed from
# to accounts that will need it ( --account '<contract owner wallet private key>,<ETH in wei>' )
# which follows the principle how accounts are fed by service fee amounts from this unique wallet,
# required by the state resulted from the smart contract deployment.

# linux/amd64
######################################
#node /app/ganache-core.docker.cli.js \
#  -p 18545 \
#  --networkId 2 \
#  --verbose \
#  --mnemonic "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term toddler sphere ripple idle dragon curious hold" \
#  --defaultBalanceEther 0 \
#  --account '0xd4670b314ecb5e6b44b7fbe625ed746522c906316e66df31be64194ee6189188,10000000000000000000000'

# linux/arm64 (for MacOs VMs, in case the upper one did not work for you)
######################################
ganache-cli \
  -h 0.0.0.0 \
  -p 18545 \
  --networkId 2 \
  --verbose \
  -m "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term toddler sphere ripple idle dragon curious hold" \
  --defaultBalanceEther 0 \
  --account '0xd4670b314ecb5e6b44b7fbe625ed746522c906316e66df31be64194ee6189188,10000000000000000000000'
