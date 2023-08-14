// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent::{
    AgentDigest, PayablePaymentsAgent,
};
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
#[cfg(test)]
use std::any::Any;
use web3::types::U256;

#[derive(Debug, Clone)]
pub struct PayablePaymentsAgentWeb3 {
    gas_limit_const_part: u64,
    maximum_added_gas_margin: u64,
    consuming_wallet_balances_opt: Option<ConsumingWalletBalances>,
    gwei_per_computed_unit_opt: Option<u64>,
}

impl PayablePaymentsAgent for PayablePaymentsAgentWeb3 {
    fn set_agreed_fee_per_computation_unit(
        &mut self,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError> {
        let gas_price_gwei = persistent_config.gas_price()?;
        self.gwei_per_computed_unit_opt = Some(gas_price_gwei);
        Ok(())
    }

    fn set_consuming_wallet_balances(&mut self, balances: ConsumingWalletBalances) {
        self.consuming_wallet_balances_opt.replace(balances);
    }

    fn estimated_transaction_fee_total(&self, number_of_transactions: usize) -> u128 {
        let gas_price = self.gwei_per_computed_unit_opt.expectv("gas price") as u128;
        let max_gas_limit = (self.maximum_added_gas_margin + self.gas_limit_const_part) as u128;
        number_of_transactions as u128 * gas_price * max_gas_limit
    }

    fn consuming_wallet_balances(&self) -> Option<ConsumingWalletBalances> {
        self.consuming_wallet_balances_opt
    }

    fn make_agent_digest(
        &self,
        blockchain_interface: &dyn BlockchainInterface,
        wallet: &Wallet,
    ) -> Result<Box<dyn AgentDigest>, BlockchainError> {
        let id = blockchain_interface.get_transaction_count(wallet)?;
        let gas_price_gwei = self.gwei_per_computed_unit_opt.expectv("gas price");
        Ok(Box::new(AgentDigestWeb3::new(gas_price_gwei, id)))
    }
}

// 64 * (64 - 12) ... std transaction has data of 64 bytes and 12 bytes are never used with us;
// each non-zero byte costs 64 units of gas
pub const WEB3_MAXIMAL_GAS_LIMIT_MARGIN: u64 = 3328;

impl PayablePaymentsAgentWeb3 {
    pub fn new(gas_limit_const_part: u64) -> Self {
        Self {
            gas_limit_const_part,
            maximum_added_gas_margin: WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
            consuming_wallet_balances_opt: None,
            gwei_per_computed_unit_opt: None,
        }
    }
}

pub struct AgentDigestWeb3 {
    gas_price_gwei: u64,
    pending_transaction_id: U256,
}

impl AgentDigest for AgentDigestWeb3 {
    fn agreed_fee_per_computation_unit(&self) -> u64 {
        self.gas_price_gwei
    }

    fn pending_transaction_id(&self) -> U256 {
        self.pending_transaction_id
    }

    implement_as_any!();
}

impl AgentDigestWeb3 {
    pub fn new(gas_price_gwei: u64, pending_transaction_id: U256) -> Self {
        Self {
            gas_price_gwei,
            pending_transaction_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent::{
        AgentDigest, PayablePaymentsAgent,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::{
        AgentDigestWeb3, PayablePaymentsAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::make_wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use std::sync::{Arc, Mutex};
    use web3::types::U256;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3328)
    }

    #[test]
    fn payable_payments_agent_is_constructed_with_right_values() {
        let subject = PayablePaymentsAgentWeb3::new(455);

        assert_eq!(subject.gas_limit_const_part, 455);
        assert_eq!(
            subject.maximum_added_gas_margin,
            WEB3_MAXIMAL_GAS_LIMIT_MARGIN
        );
        assert_eq!(subject.gwei_per_computed_unit_opt, None);
        assert_eq!(subject.consuming_wallet_balances_opt, None)
    }

    #[test]
    fn set_and_get_methods_for_agreed_fee_per_computation_unit_sad_path() {
        let persistent_config = PersistentConfigurationMock::default()
            .gas_price_result(Err(PersistentConfigError::TransactionError));
        let mut subject = PayablePaymentsAgentWeb3::new(12345);

        let result = subject.set_agreed_fee_per_computation_unit(&persistent_config);

        assert_eq!(result, Err(PersistentConfigError::TransactionError));
    }

    #[test]
    fn set_and_get_methods_for_consuming_wallet_balances_work() {
        let mut subject = PayablePaymentsAgentWeb3::new(12345);
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::from(45_000),
            masq_token_balance_in_minor_units: U256::from(30_000),
        };

        subject.set_consuming_wallet_balances(consuming_wallet_balances.clone());

        assert_eq!(
            subject.consuming_wallet_balances(),
            Some(consuming_wallet_balances)
        )
    }

    #[test]
    fn estimated_transaction_fee_works() {
        let persistent_config = PersistentConfigurationMock::default()
            .gas_price_result(Ok(122))
            .gas_price_result(Ok(550));
        let mut one_agent = PayablePaymentsAgentWeb3::new(11_111);
        let mut second_agent = PayablePaymentsAgentWeb3::new(444);

        one_agent
            .set_agreed_fee_per_computation_unit(&persistent_config)
            .unwrap();
        second_agent
            .set_agreed_fee_per_computation_unit(&persistent_config)
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
    fn make_agent_digest_happy_path() {
        let get_transaction_count_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = PayablePaymentsAgentWeb3::new(12345);
        subject.gwei_per_computed_unit_opt = Some(234);
        let consuming_wallet = make_wallet("efg");
        let blockchain_interface = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(U256::from(45)));

        let result = subject
            .make_agent_digest(&blockchain_interface, &consuming_wallet)
            .unwrap();

        let digest = result.as_any().downcast_ref::<AgentDigestWeb3>().unwrap();
        assert_eq!(digest.agreed_fee_per_computation_unit(), 234);
        assert_eq!(digest.pending_transaction_id(), U256::from(45));
    }

    #[test]
    fn make_agent_digest_sad_path() {
        let subject = PayablePaymentsAgentWeb3::new(12345);
        let consuming_wallet = make_wallet("efg");
        let blockchain_interface = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Err(BlockchainError::InvalidResponse));

        let result = subject.make_agent_digest(&blockchain_interface, &consuming_wallet);

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("we expected error but got ok"),
        };
        assert_eq!(err, BlockchainError::InvalidResponse);
    }

    #[test]
    fn agreed_fee_per_computation_unit_works() {
        let subject = AgentDigestWeb3::new(111, U256::from(33));

        assert_eq!(subject.agreed_fee_per_computation_unit(), 111)
    }

    #[test]
    fn pending_transaction_id_works() {
        let subject = AgentDigestWeb3::new(111, U256::from(33));

        assert_eq!(subject.pending_transaction_id(), U256::from(33))
    }
}
