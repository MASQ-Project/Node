// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use web3::types::U256;

#[derive(Debug, Clone)]
pub struct PayablePaymentsAgentWeb3 {
    gas_limit_const_part: u64,
    upmost_added_gas_margin: u64,
    consuming_wallet_balance_opt: Option<ConsumingWalletBalances>,
    pending_transaction_id_opt: Option<U256>,
    desired_fee_per_computed_unit_gwei_opt: Option<u64>,
}

impl PayablePaymentsAgent for PayablePaymentsAgentWeb3 {
    fn deliberate_required_fee_per_computed_unit(
        &mut self,
        consultant: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError> {
        let gas_price_gwei = consultant.gas_price()?;
        self.desired_fee_per_computed_unit_gwei_opt = Some(gas_price_gwei);
        Ok(())
    }

    fn set_up_pending_transaction_id(&mut self, id: U256) {
        self.pending_transaction_id_opt.replace(id);
    }

    fn set_up_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances) {
        self.consuming_wallet_balance_opt.replace(balances);
    }

    fn estimated_transaction_fee_total(&self, number_of_transactions: usize) -> u128 {
        ((self.upmost_added_gas_margin + self.gas_limit_const_part) * number_of_transactions as u64)
            as u128
            * self
                .desired_fee_per_computed_unit_gwei_opt
                .expect("yet unset gas price") as u128
    }

    fn consuming_wallet_balances(&self) -> Option<ConsumingWalletBalances> {
        self.consuming_wallet_balance_opt
    }

    fn required_fee_per_computed_unit(&self) -> Option<u64> {
        self.desired_fee_per_computed_unit_gwei_opt
    }

    fn pending_transaction_id(&self) -> Option<U256> {
        self.pending_transaction_id_opt
    }

    fn debug(&self) -> String {
        format!("{:?}", self)
    }

    fn duplicate(&self) -> Box<dyn PayablePaymentsAgent> {
        Box::new(self.clone())
    }
}

// 64 * (64 - 12) ... std transaction has data of 64 bytes and 12 bytes are never used with us;
// each non-zero byte costs 64 units of gas
pub const WEB3_MAXIMAL_GAS_LIMIT_MARGIN: u64 = 3328;

impl PayablePaymentsAgentWeb3 {
    pub fn new(gas_limit_const_part: u64) -> Self {
        Self {
            gas_limit_const_part,
            upmost_added_gas_margin: WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
            consuming_wallet_balance_opt: None,
            pending_transaction_id_opt: None,
            desired_fee_per_computed_unit_gwei_opt: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
    use crate::accountant::scanners::payable_payments_agent_web3::{
        PayablePaymentsAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::accountant::test_utils::assert_on_cloneable_agent_objects;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use web3::types::U256;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3328)
    }

    #[test]
    fn payable_payments_agent_is_properly_constructed() {
        let subject = PayablePaymentsAgentWeb3::new(455);

        assert_eq!(subject.gas_limit_const_part, 455);
        assert_eq!(
            subject.upmost_added_gas_margin,
            WEB3_MAXIMAL_GAS_LIMIT_MARGIN
        );
        assert_eq!(subject.pending_transaction_id_opt, None);
        assert_eq!(subject.desired_fee_per_computed_unit_gwei_opt, None);
        assert_eq!(subject.consuming_wallet_balance_opt, None)
    }

    #[test]
    fn set_and_get_for_price_per_computed_unit_happy_path() {
        let persistent_config = PersistentConfigurationMock::default().gas_price_result(Ok(130));
        let mut subject = PayablePaymentsAgentWeb3::new(12345);

        let result = subject.deliberate_required_fee_per_computed_unit(&persistent_config);

        assert_eq!(result, Ok(()));
        assert_eq!(subject.required_fee_per_computed_unit(), Some(130))
    }

    #[test]
    fn set_and_get_for_price_per_computed_unit_sad_path() {
        let persistent_config = PersistentConfigurationMock::default()
            .gas_price_result(Err(PersistentConfigError::TransactionError));
        let mut subject = PayablePaymentsAgentWeb3::new(12345);

        let result = subject.deliberate_required_fee_per_computed_unit(&persistent_config);

        assert_eq!(result, Err(PersistentConfigError::TransactionError));
    }

    #[test]
    fn set_and_get_for_pending_transaction_id_works() {
        let mut subject = PayablePaymentsAgentWeb3::new(12345);

        subject.set_up_pending_transaction_id(U256::from(654));

        assert_eq!(subject.pending_transaction_id(), Some(U256::from(654)))
    }

    #[test]
    fn set_and_get_for_consuming_wallet_balances_works() {
        let mut subject = PayablePaymentsAgentWeb3::new(12345);
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::from(45_000),
            masq_token_balance_in_minor_units: U256::from(30_000),
        };

        subject.set_up_consuming_wallet_balances(consuming_wallet_balances.clone());

        assert_eq!(
            subject.consuming_wallet_balances(),
            Some(consuming_wallet_balances)
        )
    }

    #[test]
    fn estimated_transaction_fee_works() {
        let mut one_agent = PayablePaymentsAgentWeb3::new(11_111);
        let persistent_config = PersistentConfigurationMock::default()
            .gas_price_result(Ok(122))
            .gas_price_result(Ok(550));
        one_agent
            .deliberate_required_fee_per_computed_unit(&persistent_config)
            .unwrap();
        let mut second_agent = PayablePaymentsAgentWeb3::new(444);
        second_agent
            .deliberate_required_fee_per_computed_unit(&persistent_config)
            .unwrap();

        assert_eq!(
            one_agent.estimated_transaction_fee_total(7),
            (7 * (11_111 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)) as u128 * 122
        );
        assert_eq!(
            second_agent.estimated_transaction_fee_total(3),
            (3 * (444 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)) as u128 * 550
        )
    }

    #[test]
    fn debug_works() {
        let subject = PayablePaymentsAgentWeb3::new(789);
        let std_debug = format!("{:?}", subject);

        let debug_from_trait = subject.debug();

        assert_eq!(debug_from_trait, std_debug)
    }

    #[test]
    fn duplicate_works() {
        assert_on_cloneable_agent_objects(|original_object: PayablePaymentsAgentWeb3| {
            original_object.duplicate()
        })
    }
}
