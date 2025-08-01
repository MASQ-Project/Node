use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::{
    PricedNewTxTemplate, PricedNewTxTemplates,
};
use crate::accountant::scanners::payable_scanner::data_structures::priced_retry_tx_template::PricedRetryTxTemplate;
use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
use crate::accountant::test_utils::make_payable_account;
use masq_lib::constants::DEFAULT_GAS_PRICE;
// pub fn make_priced_new_tx_template(
//     payable_account: &PayableAccount,
//     gas_price_wei: u128,
// ) -> PricedNewTxTemplate {
//     PricedNewTxTemplate {
//         base: BaseTxTemplate::from(payable_account),
//         computed_gas_price_wei: gas_price_wei,
//     }
// }

pub fn make_priced_new_tx_templates(vec: Vec<(PayableAccount, u128)>) -> PricedNewTxTemplates {
    vec.iter()
        .map(|(payable_account, gas_price_wei)| PricedNewTxTemplate {
            base: BaseTxTemplate::from(payable_account),
            computed_gas_price_wei: *gas_price_wei,
        })
        .collect()
}

pub fn make_priced_new_tx_template(n: u64) -> PricedNewTxTemplate {
    PricedNewTxTemplate {
        base: BaseTxTemplate::from(&make_payable_account(n)),
        computed_gas_price_wei: DEFAULT_GAS_PRICE as u128,
    }
}

pub fn make_priced_retry_tx_template(n: u64) -> PricedRetryTxTemplate {
    PricedRetryTxTemplate {
        base: BaseTxTemplate::from(&make_payable_account(n)),
        prev_nonce: n,
        computed_gas_price_wei: DEFAULT_GAS_PRICE as u128,
    }
}
