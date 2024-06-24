// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethereum_types::{U256, U64};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::CONTRACT_ABI;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use crate::blockchain::blockchain_interface::lower_level_interface::{
    LatestBlockNumber, LowBlockchainInt, ResultForBalance, ResultForNonce,
};
use crate::sub_lib::wallet::Wallet;
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
                .map_err(|e| BlockchainError::QueryFailed(e.to_string())),
        )
    }

    fn get_gas_price(&self) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3.eth().gas_price()
                .map_err(|e|  BlockchainError::QueryFailed(e.to_string()) )
        )
    }

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>> {
        Box::new(
            self.web3.eth()
                .block_number()
                .map_err(|e| BlockchainError::QueryFailed(e.to_string())),
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
                    BlockchainError::QueryFailed(format!("{} for wallet {}", e, address))
                }),
        )
    }

    // fn dup(&self) -> Box<dyn LowBlockchainInt> {
    //     todo!("GH-744: Delete this");
    //     // Box::new(LowBlockchainIntWeb3::new(
    //     //     self.web3.clone(),
    //     //     self.transport.clone(),
    //     //     // self._batch_web3.clone(),
    //     //     // self.contract.clone()
    //     //     // self.chain,
    //     //     // self._event_loop_handle,
    //     // ))
    // }
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
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::LowBlockchainIntWeb3;
    use crate::blockchain::blockchain_interface::lower_level_interface::{LowBlockchainInt, ResultForBalance};
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::http_test_server::TestServer;
    use masq_lib::utils::find_free_port;
    use std::str::FromStr;
    use ethabi::Address;
    use futures::Future;
    use web3::transports::{Http};
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
    fn get_block_number_works_returns_an_error() {
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





    #[test]
    fn low_interface_web3_get_masq_balance_works() {
        todo!("GH-744: This test will be replaced");
        // let port = find_free_port();
        // let test_server = TestServer::start (port, vec![
        //     br#"{"jsonrpc":"2.0","id":0,"result":"0x00000000000000000000000000000000000000000000000000000000DEADBEEF"}"#.to_vec()
        // ]);
        // let (_event_loop_handle, transport) = Http::with_max_parallel(
        //     &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
        //     REQUESTS_IN_PARALLEL,
        // )
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = make_subject(transport, chain);
        // let subject = make_blockchain_interface_web3(Some())
        //
        // let result = subject
        //     .get_service_fee_balance(
        //         &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        //     )
        //     .unwrap();
        //
        // assert_eq!(result, U256::from(0xDEADBEEF_u64));
        // let requests = test_server.requests_so_far();
        // let bodies: Vec<Value> = requests
        //     .into_iter()
        //     .map(|request| serde_json::from_slice(&request.body()).unwrap())
        //     .collect();
        // assert_eq!(bodies[0]["method"].to_string(), "\"eth_call\"",);
        // let contract_address = chain.rec().contract;
        // assert_eq!(
        //     bodies[0]["params"][0]["to"].to_string(),
        //     format!("\"{:?}\"", contract_address),
        // );
        // assert_eq!(bodies.len(), 1)
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn low_interface_web3_get_masq_balance_returns_err_for_an_invalid_wallet() {
        todo!("GH-744: This test will be replaced");
        // let port = 8545;
        // let (_event_loop_handle, transport) = Http::with_max_parallel(
        //     &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
        //     REQUESTS_IN_PARALLEL,
        // )
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = make_subject(transport, chain);
        //
        // let result = subject.get_service_fee_balance(&Wallet::new("0x_invalid_wallet_address"));
        //
        // assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn low_interface_web3_get_masq_balance_returns_err_for_unintelligible_response() {
            todo!("GH744 - Fix this once trait declaration has changed");
        // let act = |subject: &LowBlockchainIntWeb3, address: Address| {
        //     // subject.get_service_fee_balance(address)
        // };
        //
        // assert_error_from_unintelligible_response(act, "Invalid hex");
    }

    #[test]
    fn low_interface_web3_can_fetch_latest_block_number_successfully() {
        todo!("GH-744 - Come back to this --  to use MBCSBuilder");
        // let prepare_params_arc = Arc::new(Mutex::new(vec![]));
        // let transport = TestTransport::default()
        //     .prepare_params(&prepare_params_arc)
        //     .send_result(json!("0x1e37066"));
        //
        //
        //
        // let subject = make_subject(transport, TEST_DEFAULT_CHAIN);
        //
        // let latest_block_number = subject.get_block_number().unwrap();
        //
        // assert_eq!(latest_block_number, U64::from(0x1e37066u64));
        // let mut prepare_params = prepare_params_arc.lock().unwrap();
        // let (method_name, actual_arguments) = prepare_params.remove(0);
        // assert!(prepare_params.is_empty());
        // assert_eq!(method_name, "eth_blockNumber".to_string());
        // let expected_arguments: Vec<Value> = vec![];
        // assert_eq!(actual_arguments, expected_arguments);
    }

    #[test]
    fn low_interface_web3_handles_latest_null_block_number_error() {
        todo!("GH-744 - Come back to this --  to use MBCSBuilder");
        // let prepare_params_arc = Arc::new(Mutex::new(vec![]));
        // let transport = TestTransport::default()
        //     .prepare_params(&prepare_params_arc)
        //     .send_result(Value::Null);
        // let subject = make_subject(transport, TEST_DEFAULT_CHAIN);
        //
        // let expected_error = subject.get_block_number().unwrap_err();
        //
        // assert_eq!(
        //     expected_error,
        //     BlockchainError::QueryFailed(
        //         "Decoder error: Error(\"invalid type: null, expected \
        //     a 0x-prefixed hex string with length between (0; 16]\", line: 0, column: 0)"
        //             .to_string()
        //     )
        // );
        // let mut prepare_params = prepare_params_arc.lock().unwrap();
        // let (method_name, actual_arguments) = prepare_params.remove(0);
        // assert!(prepare_params.is_empty());
        // assert_eq!(method_name, "eth_blockNumber".to_string());
        // let expected_arguments: Vec<Value> = vec![];
        // assert_eq!(actual_arguments, expected_arguments);
    }

    #[test]
    fn low_interface_web3_can_handle_latest_string_block_number_error() {
        todo!("GH-744 - Come back to this --  to use MBCSBuilder");
        // let prepare_params_arc: Arc<Mutex<Vec<(String, Vec<Value>)>>> =
        //     Arc::new(Mutex::new(vec![]));
        // let transport = TestTransport::default()
        //     .prepare_params(&prepare_params_arc)
        //     .send_result(Value::String("this is an invalid block number".to_string()));
        // let subject = make_subject(transport, TEST_DEFAULT_CHAIN);
        //
        // let expected_error = subject.get_block_number().unwrap_err();
        //
        // assert_eq!(
        //     expected_error,
        //     BlockchainError::QueryFailed(
        //         "Decoder error: Error(\"0x prefix is missing\", line: 0, column: 0)".to_string()
        //     )
        // );
        // let mut prepare_params = prepare_params_arc.lock().unwrap();
        // let (method_name, actual_arguments) = prepare_params.remove(0);
        // assert!(prepare_params.is_empty());
        // assert_eq!(method_name, "eth_blockNumber".to_string());
        // let expected_arguments: Vec<Value> = vec![];
        // assert_eq!(actual_arguments, expected_arguments);
    }

    #[test]
    fn low_interface_web3_get_transaction_id_works() {
        todo!("GH-744 - Come back to this --  to use MBCSBuilder");
        // let prepare_params_arc = Arc::new(Mutex::new(vec![]));
        // let send_params_arc = Arc::new(Mutex::new(vec![]));
        // let transport = TestTransport::default()
        //     .prepare_params(&prepare_params_arc)
        //     .send_params(&send_params_arc)
        //     .send_result(json!(
        //         "0x0000000000000000000000000000000000000000000000000000000000000001"
        //     ));
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = make_subject(transport, chain);
        //
        // let result = subject.get_transaction_id(&make_paying_wallet(b"gdasgsa"));
        //
        // assert_eq!(result, Ok(U256::from(1)));
        // let mut prepare_params = prepare_params_arc.lock().unwrap();
        // let (method_name, actual_arguments) = prepare_params.remove(0);
        // assert!(prepare_params.is_empty());
        // let actual_arguments: Vec<String> = actual_arguments
        //     .into_iter()
        //     .map(|arg| serde_json::to_string(&arg).unwrap())
        //     .collect();
        // assert_eq!(method_name, "eth_getTransactionCount".to_string());
        // assert_eq!(
        //     actual_arguments,
        //     vec![
        //         String::from(r#""0x5c361ba8d82fcf0e5538b2a823e9d457a2296725""#),
        //         String::from(r#""pending""#),
        //     ]
        // );
        // let send_params = send_params_arc.lock().unwrap();
        // let rpc_call_params = vec![
        //     Value::String(String::from("0x5c361ba8d82fcf0e5538b2a823e9d457a2296725")),
        //     Value::String(String::from("pending")),
        // ];
        // let expected_request =
        //     web3::helpers::build_request(1, "eth_getTransactionCount", rpc_call_params);
        // assert_eq!(*send_params, vec![(1, expected_request)])
    }

    #[test]
    fn low_interface_web3_get_transaction_id_handles_err() {
        todo!("GH-744 - Come back to this --  to use MBCSBuilder");
        // let act = |subject: &LowBlockchainIntWeb3<Http>, wallet: &Wallet| {
        //     subject.get_transaction_id(wallet)
        // };
        //
        // assert_error_from_unintelligible_response(act, "invalid hex character")
    }

    fn assert_error_from_unintelligible_response<F>(act: F, expected_err_fragment: &str)
    where
        F: FnOnce(Box<dyn LowBlockchainInt>, Address) -> ResultForBalance,
    {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFQ"}"#.to_vec()
        ]);
        // let (_event_loop_handle, transport) = Http::with_max_parallel(
        //     &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
        //     REQUESTS_IN_PARALLEL,
        // )
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let address = Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap().address();
        // let subject = make_subject(transport, TEST_DEFAULT_CHAIN);

        let subject = make_blockchain_interface_web3(Some(port));
        let address = Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap().address();

        let result = act(subject.lower_interface(), address);

        let err_msg = match result {
            Err(BlockchainError::QueryFailed(msg)) => msg,
            x => panic!("Expected BlockchainError::QueryFailed, but got {:?}", x),
        };
        assert!(
            err_msg.contains(expected_err_fragment),
            "Expected this fragment \"{}\" in this err msg: {}",
            expected_err_fragment,
            err_msg
        );
        assert!(
            err_msg.contains("for wallet 0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
            "Expected the wallet to be cited in the err msg like \" for wallet {}\" but wasn't",
            address
        )
    }

    fn make_subject(transport: Http, contract_address: Address) -> LowBlockchainIntWeb3 {
        // let web3 = Web3::new(transport.clone());
        // let web3_batch = Web3::new(Batch::new(transport.clone()));
        // let contract =
        //     Contract::from_json(web3.eth(), chain.rec().contract, CONTRACT_ABI.as_bytes())
        //         .expect("Unable to initialize contract.");
        // LowBlockchainIntWeb3::new(Rc::new(web3), Rc::new(web3_batch), contract)
        LowBlockchainIntWeb3::new(transport, contract_address)
    }
}
