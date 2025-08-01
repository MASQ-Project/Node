use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::{
    PricedNewTxTemplate, PricedNewTxTemplates,
};
use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;

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
