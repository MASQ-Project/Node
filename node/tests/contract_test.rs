// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethabi;
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use web3;
use web3::contract::Options;

fn assert_contract(
    blockchain_url: &str,
    chain: &Chain,
    expected_token_name: &str,
    expected_decimals: u32,
) {
    let (_event_loop, transport) = web3::transports::Http::new(blockchain_url).unwrap();
    let web3 = web3::Web3::new(transport);
    let address = chain.rec().contract;
    let min_abi_json = r#"[{
        "constant": true,
        "inputs": [],
        "name": "name",
        "outputs": [
            {
                "name": "",
                "type": "string"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
        {
        "constant": true,
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "name": "",
                "type": "uint8"
            }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    }]"#;
    let abi = ethabi::Contract::load(min_abi_json.as_bytes()).unwrap();
    let contract = web3::contract::Contract::new(web3.eth(), address, abi);

    let token_name: String = contract
        .query("name", (), None, Options::default(), None)
        .wait()
        .unwrap();

    let decimals: u32 = contract
        .query("decimals", (), None, Options::default(), None)
        .wait()
        .unwrap();

    assert_eq!(token_name, expected_token_name);
    assert_eq!(decimals, expected_decimals);
}

#[test]
fn masq_erc20_contract_exists_on_polygon_mumbai_integration() {
    let blockchain_url = "https://rpc-mumbai.matic.today/";
    let chain = Chain::PolyMumbai;

    assert_contract(blockchain_url, &chain, "tMASQ", 18)
}

#[test]
fn masq_erc20_contract_exists_on_polygon_mainnet_integration() {
    let blockchain_url = "https://polygon-rpc.com/";
    let chain = Chain::PolyMainnet;

    assert_contract(blockchain_url, &chain, "MASQ (PoS)", 18)
}

#[test]
fn masq_erc20_contract_exists_on_ethereum_mainnet_integration() {
    let blockchain_url = "https://mainnet.infura.io/v3/0ead23143b174f6983c76f69ddcf4026";
    let chain = Chain::EthMainnet;

    assert_contract(blockchain_url, &chain, "MASQ", 18)
}

#[test]
fn masq_erc20_contract_exists_on_ethereum_ropsten_integration() {
    let blockchain_url = "https://ropsten.infura.io/v3/0ead23143b174f6983c76f69ddcf4026";
    let chain = Chain::EthRopsten;

    assert_contract(blockchain_url, &chain, "Shroud", 18)
}
