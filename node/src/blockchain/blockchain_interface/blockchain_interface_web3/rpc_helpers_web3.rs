// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::rpc_helpers::{
    RPCHelpers, ResultForBalance, ResultForNonce,
};
use crate::blockchain::blockchain_interface::BlockchainError;
use crate::sub_lib::wallet::Wallet;
use futures::Future;
use std::rc::Rc;
use web3::contract::{Contract, Options};
use web3::transports::Batch;
use web3::types::BlockNumber;
use web3::{BatchTransport, Web3};

pub struct RPCHelpersWeb3<T>
where
    T: BatchTransport,
{
    web3: Rc<Web3<T>>,
    // TODO waiting for GH-707 (note: consider to query the balances together with the id)
    _batch_web3: Rc<Web3<Batch<T>>>,
    contract: Contract<T>,
}

impl<T> RPCHelpers for RPCHelpersWeb3<T>
where
    T: BatchTransport,
{
    fn get_transaction_fee_balance(&self, wallet: &Wallet) -> ResultForBalance {
        self.web3
            .eth()
            .balance(wallet.address(), None)
            .map_err(|e| BlockchainError::QueryFailed(format!("{} for wallet {}", e, wallet)))
            .wait()
    }

    fn get_masq_balance(&self, wallet: &Wallet) -> ResultForBalance {
        self.contract
            .query(
                "balanceOf",
                wallet.address(),
                None,
                Options::default(),
                None,
            )
            .map_err(|e| BlockchainError::QueryFailed(format!("{} for wallet {}", e, wallet)))
            .wait()
    }

    fn get_transaction_id(&self, wallet: &Wallet) -> ResultForNonce {
        self.web3
            .eth()
            .transaction_count(wallet.address(), Some(BlockNumber::Pending))
            .map_err(|e| BlockchainError::QueryFailed(format!("{} for wallet {}", e, wallet)))
            .wait()
    }
}

impl<T> RPCHelpersWeb3<T>
where
    T: BatchTransport,
{
    pub fn new(web3: Rc<Web3<T>>, batch_web3: Rc<Web3<Batch<T>>>, contract: Contract<T>) -> Self {
        Self {
            web3,
            _batch_web3: batch_web3,
            contract,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::rpc_helpers_web3::RPCHelpersWeb3;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        CONTRACT_ABI, REQUESTS_IN_PARALLEL,
    };
    use crate::blockchain::blockchain_interface::rpc_helpers::{RPCHelpers, ResultForBalance};
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::test_utils::TestTransport;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::http_test_server::TestServer;
    use crate::test_utils::make_paying_wallet;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use serde_json::{json, Value};
    use std::net::Ipv4Addr;
    use std::rc::Rc;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use web3::contract::Contract;
    use web3::transports::{Batch, Http};
    use web3::types::U256;
    use web3::{BatchTransport, Web3};

    #[test]
    fn get_transaction_id_works() {
        let prepare_params_arc = Arc::new(Mutex::new(vec![]));
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let transport = TestTransport::default()
            .prepare_params(&prepare_params_arc)
            .send_params(&send_params_arc)
            .send_result(json!(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ));
        let chain = TEST_DEFAULT_CHAIN;
        let subject = make_subject(transport, chain);

        let result = subject.get_transaction_id(&make_paying_wallet(b"gdasgsa"));

        assert_eq!(result, Ok(U256::from(1)));
        let mut prepare_params = prepare_params_arc.lock().unwrap();
        let (method_name, actual_arguments) = prepare_params.remove(0);
        assert!(prepare_params.is_empty());
        let actual_arguments: Vec<String> = actual_arguments
            .into_iter()
            .map(|arg| serde_json::to_string(&arg).unwrap())
            .collect();
        assert_eq!(method_name, "eth_getTransactionCount".to_string());
        assert_eq!(
            actual_arguments,
            vec![
                String::from(r#""0x5c361ba8d82fcf0e5538b2a823e9d457a2296725""#),
                String::from(r#""pending""#),
            ]
        );
        let send_params = send_params_arc.lock().unwrap();
        let rpc_call_params = vec![
            Value::String(String::from("0x5c361ba8d82fcf0e5538b2a823e9d457a2296725")),
            Value::String(String::from("pending")),
        ];
        let expected_request =
            web3::helpers::build_request(1, "eth_getTransactionCount", rpc_call_params);
        assert_eq!(*send_params, vec![(1, expected_request)])
    }

    #[test]
    fn get_transaction_id_handles_err() {
        let act =
            |subject: &RPCHelpersWeb3<Http>, wallet: &Wallet| subject.get_transaction_id(wallet);

        assert_error_from_unintelligible_response(act, "invalid hex character")
    }

    #[test]
    fn transaction_fee_balance_works() {
        let port = find_free_port();
        let test_server = TestServer::start(
            port,
            vec![br#"{"jsonrpc":"2.0","id":0,"result":"0xDEADBEEF"}"#.to_vec()],
        );
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let subject = make_subject(transport, chain);

        let result = subject
            .get_transaction_fee_balance(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .unwrap();

        assert_eq!(result, U256::from(3_735_928_559_u64));
        let requests = test_server.requests_so_far();
        let bodies: Vec<Value> = requests
            .into_iter()
            .map(|request| serde_json::from_slice(&request.body()).unwrap())
            .collect();
        assert_eq!(bodies[0]["method"].to_string(), "\"eth_getBalance\"",);
        assert_eq!(
            bodies[0]["params"][0].to_string(),
            "\"0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc\"",
        );
        assert_eq!(bodies.len(), 1)
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn get_transaction_fee_balance_returns_err_for_an_invalid_wallet() {
        let port = 8545;
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let subject = make_subject(transport, chain);

        let result = subject.get_transaction_fee_balance(&Wallet::new("0x_invalid_wallet_address"));

        assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn get_transaction_fee_balance_returns_err_for_unintelligible_response() {
        let act = |subject: &RPCHelpersWeb3<Http>, wallet: &Wallet| {
            subject.get_transaction_fee_balance(wallet)
        };

        assert_error_from_unintelligible_response(act, "invalid hex character");
    }

    #[test]
    fn get_masq_balance_works() {
        let port = find_free_port();
        let test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":0,"result":"0x00000000000000000000000000000000000000000000000000000000DEADBEEF"}"#.to_vec()
        ]);
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let subject = make_subject(transport, chain);

        let result = subject
            .get_masq_balance(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .unwrap();

        assert_eq!(result, U256::from(3_735_928_559_u64));
        let requests = test_server.requests_so_far();
        let bodies: Vec<Value> = requests
            .into_iter()
            .map(|request| serde_json::from_slice(&request.body()).unwrap())
            .collect();
        assert_eq!(bodies[0]["method"].to_string(), "\"eth_call\"",);
        let contract_address = chain.rec().contract;
        assert_eq!(
            bodies[0]["params"][0]["to"].to_string(),
            format!("\"{:?}\"", contract_address),
        );
        assert_eq!(bodies.len(), 1)
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn get_masq_balance_returns_err_for_an_invalid_wallet() {
        let port = 8545;
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let subject = make_subject(transport, chain);

        let result = subject.get_masq_balance(&Wallet::new("0x_invalid_wallet_address"));

        assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn get_masq_balance_returns_err_for_unintelligible_response() {
        let act =
            |subject: &RPCHelpersWeb3<Http>, wallet: &Wallet| subject.get_masq_balance(wallet);

        assert_error_from_unintelligible_response(act, "Invalid hex");
    }

    fn assert_error_from_unintelligible_response<F>(act: F, expected_err_fragment: &str)
    where
        F: FnOnce(&RPCHelpersWeb3<Http>, &Wallet) -> ResultForBalance,
    {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFQ"}"#.to_vec()
        ]);
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let wallet = Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let subject = make_subject(transport, chain);

        let result = act(&subject, &wallet);

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
            wallet
        )
    }

    fn make_subject<T>(transport: T, chain: Chain) -> RPCHelpersWeb3<T>
    where
        T: BatchTransport,
    {
        let web3 = Web3::new(transport.clone());
        let web3_batch = Web3::new(Batch::new(transport.clone()));
        let contract =
            Contract::from_json(web3.eth(), chain.rec().contract, CONTRACT_ABI.as_bytes())
                .expect("Unable to initialize contract.");
        RPCHelpersWeb3::new(Rc::new(web3), Rc::new(web3_batch), contract)
    }
}
