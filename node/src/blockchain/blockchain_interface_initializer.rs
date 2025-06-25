// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
};
use crate::blockchain::blockchain_interface::BlockchainInterface;
use masq_lib::blockchains::chains::Chain;
use web3::transports::Http;

pub(in crate::blockchain) struct BlockchainInterfaceInitializer {}

impl BlockchainInterfaceInitializer {
    // TODO if we ever have multiple chains of fundamentally different architectures and are able
    // to switch them, this should probably be replaced by a HashMap of distinct interfaces for
    // each chain
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
    use crate::accountant::scanners::payable_scanner_extension::msgs::{
        PricedQualifiedPayables, QualifiedPayablesWithGasPrice, UnpricedQualifiedPayables,
    };
    use crate::accountant::test_utils::make_payable_account;
    use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
    use crate::blockchain::blockchain_interface_initializer::BlockchainInterfaceInitializer;
    use crate::test_utils::make_wallet;
    use futures::Future;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::utils::find_free_port;
    use std::net::Ipv4Addr;

    #[test]
    fn initialize_web3_interface_works() {
        // TODO this test should definitely assert on the web3 requests sent to the server,
        // that's the best way to verify that this interface belongs to the web3 architecture
        // (This test amplifies the importance of GH-543)
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
        let chain = Chain::PolyMainnet;
        let server_url = &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port);

        let result = BlockchainInterfaceInitializer {}.initialize_interface(server_url, chain);

        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let qualified_payables_without_price =
            UnpricedQualifiedPayables::from(vec![account_1.clone(), account_2.clone()]);
        let payable_wallet = make_wallet("payable");
        let blockchain_agent = result
            .introduce_blockchain_agent(payable_wallet.clone())
            .wait()
            .unwrap();
        assert_eq!(blockchain_agent.consuming_wallet(), &payable_wallet);
        let priced_qualified_payables =
            blockchain_agent.price_qualified_payables(qualified_payables_without_price);
        let gas_price_with_margin = increase_gas_price_by_margin(1_000_000_000);
        let expected_priced_qualified_payables = PricedQualifiedPayables {
            payables: vec![
                QualifiedPayablesWithGasPrice::new(account_1, gas_price_with_margin),
                QualifiedPayablesWithGasPrice::new(account_2, gas_price_with_margin),
            ],
        };
        assert_eq!(
            priced_qualified_payables,
            expected_priced_qualified_payables
        );
        assert_eq!(
            blockchain_agent.estimated_transaction_fee_total(&priced_qualified_payables),
            190_652_800_000_000
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
