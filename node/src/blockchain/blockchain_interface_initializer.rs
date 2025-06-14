// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
};
use crate::blockchain::blockchain_interface::BlockchainInterface;
use masq_lib::blockchains::chains::Chain;
use web3::transports::Http;

pub(in crate::blockchain) struct BlockchainInterfaceInitializer {}

impl BlockchainInterfaceInitializer {
    // TODO when we have multiple chains of fundamentally different architectures and are able to switch them,
    // this should probably be replaced by a HashMap of distinct interfaces for each chain
    pub fn initialize_interface(
        &self,
        blockchain_service_url: &str,
        chain: Chain,
    ) -> Box<dyn BlockchainInterface> {
        self.initialize_web3_interface(blockchain_service_url, chain)
    }

    fn initialize_web3_interface(
        &self,
        blockchain_service_url: &str,
        chain: Chain,
    ) -> Box<dyn BlockchainInterface> {
        match Http::with_max_parallel(blockchain_service_url, REQUESTS_IN_PARALLEL) {
            Ok((event_loop_handle, transport)) => Box::new(BlockchainInterfaceWeb3::new(
                transport,
                event_loop_handle,
                chain,
            )),
            Err(e) => panic!(
                "Invalid blockchain service URL \"{}\". Error: {:?}. Chain: {}",
                blockchain_service_url,
                e,
                chain.rec().literal_identifier
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface_initializer::BlockchainInterfaceInitializer;
    use masq_lib::blockchains::chains::Chain;
    use futures::Future;
    use std::net::Ipv4Addr;
    use crate::blockchain::blockchain_interface::BlockchainInterface;
    use crate::test_utils::make_wallet;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::utils::find_free_port;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::{QualifiedPayableWithGasPrice, QualifiedPayablesRawPack, QualifiedPayablesRipePack};
    use crate::accountant::test_utils::make_payable_account;
    use crate::blockchain::test_utils::increase_gas_price_by_marginal;

    #[test]
    fn initialize_web3_interface_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0) // gas_price = 10000000000
            .ok_response("0xFF40".to_string(), 0)
            .ok_response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .ok_response("0x23".to_string(), 1)
            .start();
        let wallet = make_wallet("123");
        let chain = Chain::PolyMainnet;
        let server_url = &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port);

        let result = BlockchainInterfaceInitializer{}.initialize_interface(server_url, chain);

        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let raw_qualified_payables = QualifiedPayablesRawPack::from(vec![account_1.clone(), account_2.clone()]);
        let payable_wallet = make_wallet("payable");
        let (blockchain_agent, ripe_qualified_payables) = result
            .introduce_blockchain_agent(raw_qualified_payables, payable_wallet)
            .wait()
            .unwrap();
        assert_eq!(blockchain_agent.consuming_wallet(), &wallet);
        let gas_price_with_margin = increase_gas_price_by_marginal(1_000_000_000, chain);
        let expected_ripe_qualified_payables = QualifiedPayablesRipePack{ payables:
        vec![QualifiedPayableWithGasPrice::new(account_1, gas_price_with_margin), QualifiedPayableWithGasPrice::new(account_2, gas_price_with_margin)]};
        assert_eq!(ripe_qualified_payables, expected_ripe_qualified_payables);
        assert_eq!(
            blockchain_agent.estimated_transaction_fee_total(),
            todo!()
        );
    }

    #[test]
    #[should_panic(expected = "Invalid blockchain service URL \"http://λ:8545\". \
    Error: Transport(\"InvalidUri(InvalidUriChar)\"). Chain: polygon-mainnet")]
    fn invalid_blockchain_url_for_produces_panic_for_web3_interface() {
        let blockchain_service_url = "http://λ:8545";
        let subject = BlockchainInterfaceInitializer {};

        subject.initialize_web3_interface(blockchain_service_url, DEFAULT_CHAIN);
    }
}
