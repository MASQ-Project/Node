// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(test)]
use crate::arbitrary_id_stamp_in_trait;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
#[cfg(test)]
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use masq_lib::test_only;
#[cfg(test)]
use std::any::Any;
use web3::types::U256;

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
    fn estimated_transaction_fee_total(&self, number_of_transactions: usize) -> u128;
    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances;
    fn agreed_fee_per_computation_unit(&self) -> u64;
    fn consuming_wallet(&self) -> &Wallet;
    fn pending_transaction_id(&self) -> U256;

    test_only!(
        fn dup(&self) -> Box<dyn BlockchainAgent> {
            intentionally_blank!()
        },
        as_any_in_trait!();,
        arbitrary_id_stamp_in_trait!();
    );
}
