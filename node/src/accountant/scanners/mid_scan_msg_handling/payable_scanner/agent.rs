// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(test)]
use crate::arbitrary_id_stamp_in_trait;
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
#[cfg(test)]
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
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

pub trait PayablePaymentsAgent: Send {
    fn set_required_fee_per_computed_unit(
        &mut self,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError>;
    fn set_pending_transaction_id(&mut self, id: U256);
    fn set_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances);
    fn estimated_transaction_fee_total(&self, number_of_transactions: usize) -> u128;
    fn consuming_wallet_balances(&self) -> Option<ConsumingWalletBalances>;
    fn required_fee_per_computed_unit(&self) -> Option<u64>;
    fn pending_transaction_id(&self) -> Option<U256>;

    #[cfg(test)]
    arbitrary_id_stamp_in_trait!();
}
