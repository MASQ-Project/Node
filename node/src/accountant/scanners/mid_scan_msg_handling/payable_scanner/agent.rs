// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(test)]
use crate::arbitrary_id_stamp_in_trait;
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
#[cfg(test)]
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
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

pub trait PayablePaymentsAgent: Send {
    fn set_agreed_fee_per_computation_unit(
        &mut self,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError>;
    fn set_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances);
    fn estimated_transaction_fee_total(&self, number_of_transactions: usize) -> u128;
    fn consuming_wallet_balances(&self) -> Option<ConsumingWalletBalances>;
    fn make_agent_digest(
        &self,
        blockchain_interface: &dyn BlockchainInterface,
        wallet: &Wallet,
    ) -> Result<Box<dyn AgentDigest>, BlockchainError>;

    #[cfg(test)]
    arbitrary_id_stamp_in_trait!();
}

// Preferably, keep the trait without setter methods. That's actually
// the idea that drove the creation of this object
pub trait AgentDigest: Send {
    fn agreed_fee_per_computation_unit(&self) -> u64;
    fn pending_transaction_id(&self) -> U256;

    declare_as_any!();
    #[cfg(test)]
    arbitrary_id_stamp_in_trait!();
}
