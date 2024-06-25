// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethereum_types::{U256, U64};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::CONTRACT_ABI;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use futures::Future;
use web3::contract::{Contract, Options};
use web3::transports::Http;
use web3::types::{Address, BlockNumber};
use web3::{Web3};
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;

pub struct LowBlockchainIntWeb3 {
    web3: Web3<Http>,
    contract: Contract<Http>,
    // TODO waiting for GH-707 (note: consider to query the balances together with the id)
}

impl LowBlockchainInt for LowBlockchainIntWeb3 {
    fn get_transaction_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .balance(address, None)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_service_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.contract
                .query("balanceOf", address, None, Options::default(), None)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_gas_price(&self) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3.eth().gas_price()
                .map_err(|e| QueryFailed(e.to_string()) )
        )
    }

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>> {
        Box::new(
            self.web3.eth()
                .block_number()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_transaction_id(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3.eth()
                .transaction_count(address, Some(BlockNumber::Pending))
                .map_err(move |e| {
                    QueryFailed(format!("{} for wallet {}", e, address))
                }),
        )
    }
}

impl LowBlockchainIntWeb3 {
    pub fn new(transport: Http, contract_address: Address) -> Self {
        let web3= Web3::new(transport);
        let contract = Contract::from_json(
            web3.eth(),
            contract_address,
            CONTRACT_ABI.as_bytes(),
        ).expect("Unable to initialize contract.");

        Self {
            web3,
            contract,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::lower_level_interface::{LowBlockchainInt};
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
    use crate::sub_lib::wallet::Wallet;
    use masq_lib::utils::find_free_port;
    use std::str::FromStr;
    use ethabi::Address;
    use futures::Future;
    use web3::types::U256;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
    use crate::blockchain::test_utils::{make_blockchain_interface_web3};
    use crate::test_utils::make_wallet;

    fn tmp_nested_get_transaction_fee_balance_future(subject: Box<dyn LowBlockchainInt>, address: Address) -> Box<dyn Future<Item = (), Error = String>> {
        Box::new(
            subject.get_transaction_fee_balance(address).map_err(|e| {
                format!("Error: 1 {:?}", e)
            }).and_then(move |balance_1| {
                subject.get_transaction_fee_balance(address).map_err(|e| {
                    format!("Error: 2 {:?}", e)
                }).and_then(move |balance_2| {
                    subject.get_transaction_fee_balance(address).map_err(|e| {
                        format!("Error: 3 {:?}", e)
                    }).and_then(move |balance_3| {
                        eprintln!("balance_1: {:?}", balance_1);
                        eprintln!("balance_2: {:?}", balance_2);
                        eprintln!("balance_3: {:?}", balance_3);
                        Ok(())
                    })
                })
            })
        )
    }

    #[test]
    fn tmp_nested_future_test() {
        let port = find_free_port();
        let blockchain_client_server = MBCSBuilder::new(port)
            .response("0xDEADBEEF".to_string(), 0)
            .response("0xDEADBEEE".to_string(), 0)
            .response("0xDEADBEED".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let wallet = make_wallet("test_wallet");
        let address = wallet.address();

        let result = tmp_nested_get_transaction_fee_balance_future(subject.lower_interface(), address);

        result.wait().expect("TODO: panic message");
    }

    #[test]
    fn get_transaction_fee_balance_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_transaction_fee_balance(wallet.address()).wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_gas_price_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response( "0x01".to_string(),1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_gas_price().wait().unwrap();

        assert_eq!(result, 1.into());
    }

    #[test]
    fn get_gas_price_returns_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(Some(port));

        let error = subject.lower_interface().get_gas_price().wait().unwrap_err();

        assert_eq!(error, QueryFailed("Transport error: Error(IncompleteMessage)".to_string()));
    }

    #[test]
    fn get_block_number_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_block_number().wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_block_number_returns_an_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("trash".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let error = subject.lower_interface().get_block_number().wait().unwrap_err();

        assert_eq!(
            error,
            QueryFailed("Decoder error: Error(\"0x prefix is missing\", line: 0, column: 0)".to_string())
        );
    }

    #[test]
    fn get_transaction_id_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();

        let result = subject.lower_interface().get_transaction_id(wallet.address()).wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_transaction_id_returns_an_error_for_unintelligible_response() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_transaction_id(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
        )
            .wait();

        match result {
            Err(BlockchainError::QueryFailed(msg)) if msg.contains("invalid hex character: Q") => {
                ()
            }
            x => panic!("Expected complaint about hex character, but got {:?}", x),
        };
    }

    #[test]
    fn get_transaction_fee_balance_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_transaction_fee_balance(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
        )
            .wait();

        match result {
            Err(BlockchainError::QueryFailed(msg)) if msg.contains("invalid hex character: Q") => {
                ()
            }
            x => panic!("Expected complaint about hex character, but got {:?}", x),
        };
    }

    #[test]
    fn get_token_balance_can_retrieve_token_balance_of_a_wallet() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(Some(port));
        let contract = blockchain_interface_web3.get_contract();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_service_fee_balance(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
        )
            .wait()
            .unwrap();

        assert_eq!(result, U256::from(65_535));
    }

    #[test]
    fn get_token_balance_returns_error_for_unintelligible_response_to_token_balance() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFQ".to_string(),
                0,
            )
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(Some(port));
        let contract = blockchain_interface_web3.get_contract();
        let expected_err_msg = "Invalid hex";
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_service_fee_balance(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
        )
            .wait();

        let err_msg = match result {
            Err(BlockchainError::QueryFailed(msg)) => msg,
            x => panic!("Expected BlockchainError::QueryFailed, but got {:?}", x),
        };
        assert!(
            err_msg.contains(expected_err_msg),
            "Expected this fragment {} in this err msg: {}",
            expected_err_msg,
            err_msg
        )
    }
}
