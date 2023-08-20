// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fmt::Debug;
use std::rc::Rc;
use web3::{BatchTransport, Web3};
use web3::transports::Batch;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use crate::blockchain::blockchain_interface::BlockchainResult;
use crate::sub_lib::wallet::Wallet;

pub trait BlockchainInterfaceHelper {
    fn get_transaction_fee_balance(&self, address: &Wallet) -> ResultForBalance;

    fn get_token_balance(&self, address: &Wallet) -> ResultForBalance;

    fn get_transaction_count(&self, address: &Wallet) -> ResultForNonce;
}

pub type ResultForBalance = BlockchainResult<web3::types::U256>;
pub type ResultForBothBalances = BlockchainResult<(web3::types::U256, web3::types::U256)>;
pub type ResultForNonce = BlockchainResult<web3::types::U256>;

pub struct BlockchainInterfaceNonClandestineHelper<T> where T: BatchTransport{
    web3: Rc<Web3<T>>,
    batch_web3: Rc<Web3<Batch<T>>>
}

impl <T> BlockchainInterfaceHelper for BlockchainInterfaceNonClandestineHelper<T> where T: BatchTransport{
    fn get_transaction_fee_balance(&self, address: &Wallet) -> ResultForBalance {
        todo!()
    }

    fn get_token_balance(&self, address: &Wallet) -> ResultForBalance {
        todo!()
    }

    fn get_transaction_count(&self, address: &Wallet) -> ResultForNonce {
        todo!()
    }
}

impl <T> BlockchainInterfaceNonClandestineHelper<T> where T: BatchTransport{
    pub fn new(web3: Rc<Web3<T>>, batch_web3: Rc<Web3<Batch<T>>>)->Self{
       Self {
           web3,
           batch_web3
       }
    }
}

#[cfg(test)]
mod tests {


    #[test]
    fn blockchain_interface_non_clandestine_can_retrieve_eth_balance_of_a_wallet() {
        todo!("fix me later");
        // let port = find_free_port();
        // let _test_server = TestServer::start(
        //     port,
        //     vec![br#"{"jsonrpc":"2.0","id":0,"result":"0xFFFF"}"#.to_vec()],
        // );
        // let (event_loop_handle, transport) = Http::with_max_parallel(
        //     &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
        //     REQUESTS_IN_PARALLEL,
        // )
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = TopLevelBlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);
        //
        // let result = subject
        //     .get_transaction_fee_balance(
        //         &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        //     )
        //     .unwrap();
        //
        // assert_eq!(result, U256::from(65_535));
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_returns_an_error_when_requesting_eth_balance_of_an_invalid_wallet(
    ) {
        todo!("fix me later")
        // let port = 8545;
        // let (event_loop_handle, transport) = Http::with_max_parallel(
        //     &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
        //     REQUESTS_IN_PARALLEL,
        // )
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = TopLevelBlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);
        //
        // let result = subject.get_transaction_fee_balance(&Wallet::new(
        //     "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ",
        // ));
        //
        // assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
    ) {
        todo!("fix me later")
        // let port = find_free_port();
        // let _test_server = TestServer::start(
        //     port,
        //     vec![br#"{"jsonrpc":"2.0","id":0,"result":"0xFFFQ"}"#.to_vec()],
        // );
        // let (event_loop_handle, transport) = Http::new(&format!(
        //     "http://{}:{}",
        //     &Ipv4Addr::LOCALHOST.to_string(),
        //     port
        // ))
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = TopLevelBlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);
        //
        // let result = subject.get_transaction_fee_balance(
        //     &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        // );
        //
        // match result {
        //     Err(BlockchainError::QueryFailed(msg)) if msg.contains("invalid hex character: Q") => {
        //         ()
        //     }
        //     x => panic!("Expected complaint about hex character, but got {:?}", x),
        // };
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_error_for_unintelligible_response_to_gas_balance(
    ) {
        todo!("fix me later");
        // let act = |subject: &TopLevelBlockchainInterfaceNonClandestine<Http>, wallet: &Wallet| {
        //     subject.get_transaction_fee_balance(wallet)
        // };
        //
        // assert_error_during_requesting_balance(act, "invalid hex character");
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_retrieve_token_balance_of_a_wallet() {
        todo!("fix me later")
        // let port = find_free_port();
        // let _test_server = TestServer::start (port, vec![
        //     br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFF"}"#.to_vec()
        // ]);
        // let (event_loop_handle, transport) = Http::with_max_parallel(
        //     &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
        //     REQUESTS_IN_PARALLEL,
        // )
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = TopLevelBlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);
        //
        // let result = subject
        //     .get_token_balance(
        //         &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        //     )
        //     .unwrap();
        //
        // assert_eq!(result, U256::from(65_535));
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_returns_an_error_when_requesting_token_balance_of_an_invalid_wallet(
    ) {
        todo!("fix me later")
        // let port = 8545;
        // let (event_loop_handle, transport) = Http::with_max_parallel(
        //     &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
        //     REQUESTS_IN_PARALLEL,
        // )
        // .unwrap();
        // let chain = TEST_DEFAULT_CHAIN;
        // let subject = TopLevelBlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);
        //
        // let result =
        //     subject.get_token_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"));
        //
        // assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_error_for_unintelligible_response_to_token_balance(
    ) {
        todo!("fix me later")
        // let act = |subject: &TopLevelBlockchainInterfaceNonClandestine<Http>, wallet: &Wallet| {
        //     subject.get_token_balance(wallet)
        // };
        //
        // assert_error_during_requesting_balance(act, "Invalid hex");
    }

}