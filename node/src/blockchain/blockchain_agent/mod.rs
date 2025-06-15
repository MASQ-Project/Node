// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
pub mod agent_null;
pub mod agent_web3;

use crate::arbitrary_id_stamp_in_trait;
use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, QualifiedPayableGasPriceSetup};
use crate::sub_lib::wallet::Wallet;
use masq_lib::blockchains::chains::Chain;
use std::collections::HashMap;
use web3::types::Address;
// Table of chains by
//
// a) adoption of the fee market (variations on "gas price")
// b) customizable limit of allowed computation ("gas limit")
//
// CHAINS                    a)  |  b)
//-------------------------------+------
// Ethereum                 yes  |  yes
// Polygon                  yes  |  yes
// Qtum                     yes  |  yes
// NEO                      yes  |  no*
// Cardano                  no   |  yes
// Bitcoin                  yes  |  no

//* defaulted limit

pub trait BlockchainAgent: Send {
    fn estimated_transaction_fee_total(&self) -> u128;
    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances;
    fn consuming_wallet(&self) -> &Wallet;
    fn get_chain(&self) -> Chain;

    #[cfg(test)]
    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }
    as_any_ref_in_trait!();
    arbitrary_id_stamp_in_trait!();
}
