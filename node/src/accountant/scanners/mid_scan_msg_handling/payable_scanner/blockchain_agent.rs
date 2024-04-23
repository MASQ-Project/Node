// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::arbitrary_id_stamp_in_trait;
use crate::sub_lib::wallet::Wallet;
use masq_lib::percentage::Percentage;
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
    fn estimated_transaction_fee_per_transaction_minor(&self) -> u128;
    fn transaction_fee_balance_minor(&self) -> U256;
    fn service_fee_balance_minor(&self) -> u128;
    fn agreed_fee_per_computation_unit(&self) -> u64;
    fn agreed_transaction_fee_margin(&self) -> Percentage;
    fn consuming_wallet(&self) -> &Wallet;
    fn pending_transaction_id(&self) -> U256;

    #[cfg(test)]
    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }
    as_any_in_trait!();
    arbitrary_id_stamp_in_trait!();
}
