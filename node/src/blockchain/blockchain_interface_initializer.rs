// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::{
    BlockchainInterface, BlockchainInterfaceNonClandestine,
};
use masq_lib::blockchains::chains::Chain;
use web3::transports::Http;

pub(in crate::blockchain) struct BlockchainInterfaceInitializer {}

impl BlockchainInterfaceInitializer {
    // TODO when we have multiple chains of fundamentally different architectures and also the ability to switch them,
    // this should probably be replaced by a HashMap of distinct blockchain interfaces for each chain
    pub fn initialize_chain_compatible_interface(
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
        match Http::new(blockchain_service_url) {
            Ok((event_loop_handle, transport)) => Box::new(BlockchainInterfaceNonClandestine::new(
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
    use crate::test_utils::http_test_server::TestServer;
    use crate::test_utils::make_wallet;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use serde_json::Value;
    use std::net::Ipv4Addr;

    #[test]
    fn initialize_web3_interface_works() {
        let port = find_free_port();
        let server_url = format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port);
        let test_server = TestServer::start(
            port,
            vec![br#"{"jsonrpc":"2.0","id":0,"result":someGarbage}"#.to_vec()],
        );
        let wallet = make_wallet("123");
        let subject = BlockchainInterfaceInitializer {};
        let chain = Chain::PolyMainnet;

        let interface = subject.initialize_web3_interface(&server_url, chain);

        //no result assertion, we anticipate a badly formatted response from the server
        let _ = interface.get_token_balance(&wallet);

        let requests = test_server.requests_so_far();
        let bodies: Vec<Value> = requests
            .into_iter()
            .map(|request| serde_json::from_slice(&request.body()).unwrap())
            .collect();
        assert_eq!(
            bodies[0]["params"][0]["data"].to_string()[35..75],
            wallet.to_string()[2..]
        );
        assert_eq!(
            bodies[0]["params"][0]["to"],
            format!("{:?}", chain.rec().contract)
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
