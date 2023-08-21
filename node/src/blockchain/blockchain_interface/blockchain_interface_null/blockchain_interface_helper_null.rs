// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::blockchain_interface_helper::{
    BlockchainInterfaceHelper, ResultForBalance, ResultForNonce,
};
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use web3::types::U256;

struct BlockchainInterfaceHelperNull {
    logger: Logger,
}

impl BlockchainInterfaceHelper for BlockchainInterfaceHelperNull {
    fn get_transaction_fee_balance(&self, _wallet: &Wallet) -> ResultForBalance {
        Ok(self.handle_null_call("transaction fee balance"))
    }

    fn get_masq_balance(&self, _wallet: &Wallet) -> ResultForBalance {
        Ok(self.handle_null_call("masq balance"))
    }

    fn get_transaction_id(&self, _wallet: &Wallet) -> ResultForNonce {
        Ok(self.handle_null_call("transaction id"))
    }
}

impl BlockchainInterfaceHelperNull {
    pub fn new(logger: &Logger) -> Self {
        Self {
            logger: logger.clone(),
        }
    }

    fn handle_null_call(&self, operation: &str) -> U256 {
        error!(
            self.logger,
            "Blockchain helper null can't fetch {operation}"
        );
        0.into()
    }
}

#[cfg(test)]
mod tests {
    use web3::types::U256;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::blockchain::blockchain_interface::blockchain_interface_helper::BlockchainInterfaceHelper;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::blockchain_interface_helper_null::BlockchainInterfaceHelperNull;
    use crate::blockchain::blockchain_interface::BlockchainError;

    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;

    #[test]
    fn helper_null_gets_no_transaction_fee_balance() {
        let test_name = "helper_null_gets_no_transaction_fee_balance";
        let act = |subject: &BlockchainInterfaceHelperNull, wallet: &Wallet| {
            subject.get_transaction_fee_balance(wallet)
        };

        test_helper_null_method(test_name, act, "transaction fee balance");
    }

    #[test]
    fn helper_null_gets_no_masq_balance() {
        let test_name = "helper_null_gets_no_masq_balance";
        let act = |subject: &BlockchainInterfaceHelperNull, wallet: &Wallet| {
            subject.get_masq_balance(wallet)
        };

        test_helper_null_method(test_name, act, "masq balance");
    }

    #[test]
    fn helper_null_gets_no_transaction_id() {
        let test_name = "helper_null_gets_no_transaction_id";
        let act = |subject: &BlockchainInterfaceHelperNull, wallet: &Wallet| {
            subject.get_transaction_id(wallet)
        };

        test_helper_null_method(test_name, act, "transaction id");
    }

    fn test_helper_null_method(
        test_name: &str,
        act: fn(&BlockchainInterfaceHelperNull, &Wallet) -> Result<U256, BlockchainError>,
        expected_method_name: &str,
    ) {
        init_test_logging();
        let wallet = make_wallet("blah");
        let subject = BlockchainInterfaceHelperNull::new(&Logger::new(test_name));

        let result = act(&subject, &wallet);

        assert_eq!(result, Ok(U256::zero()));
        let _expected_log_msg = TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Blockchain helper null can't fetch {expected_method_name}"
        ));
    }
}
