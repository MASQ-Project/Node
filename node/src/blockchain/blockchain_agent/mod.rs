// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod agent_web3;

use crate::accountant::scanners::payable_scanner::data_structures::new_tx_template::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_retry_tx_template::PricedRetryTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::RetryTxTemplates;
use crate::arbitrary_id_stamp_in_trait;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::blockchains::chains::Chain;
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
    fn price_qualified_payables(
        &self,
        unpriced_tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    ) -> Either<PricedNewTxTemplates, PricedRetryTxTemplates>;
    fn estimate_transaction_fee_total(
        &self,
        priced_tx_templates: &Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    ) -> u128;
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
