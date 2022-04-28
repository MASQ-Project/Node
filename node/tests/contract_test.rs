// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethabi;
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use web3;
use web3::contract::Options;

fn assert_contract_body(
    blockchain_service_url: &str,
    chain: &Chain,
    expected_token_name: &str,
    expected_decimals: u32,
) -> Result<(), ()> {
    eprintln!("Starting a new attempt with: '{}'", blockchain_service_url);
    let (_event_loop, transport) = web3::transports::Http::new(blockchain_service_url).unwrap();
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
    let token_name: String = match contract
        .query("name", (), None, Options::default(), None)
        .wait()
    {
        Ok(tn) => tn,
        Err(e) => {
            eprintln!("Token name query failed due to: {:?}", e);
            return Err(());
        }
    };
    let decimals: u32 = match contract
        .query("decimals", (), None, Options::default(), None)
        .wait()
    {
        Ok(dec) => dec,
        Err(e) => {
            eprintln!("Decimals query failed due to: {:?}", e);
            return Err(());
        }
    };

    match (
        (token_name == expected_token_name),
        (decimals == expected_decimals),
    ) {
        (true, true) => Ok(()),
        _ => panic!(
            "We failed to assert with values {}, {} and {}, {}",
            token_name, expected_token_name, decimals, expected_decimals
        ),
    }
}

fn assert_contract(
    blockchain_urls: Vec<&str>,
    chain: &Chain,
    expected_token_name: &str,
    expected_decimals: u32,
) {
    if !blockchain_urls.iter().fold(false, |acc, url| {
        match (
            acc,
            assert_contract_body(url, chain, expected_token_name, expected_decimals),
        ) {
            (true, _) => true,
            (false, Ok(_)) => true,
            (false, Err(_)) => false,
        }
    }) {
        panic!("Test failed on all blockchain services")
    }
}

#[test]
fn masq_erc20_contract_exists_on_polygon_mumbai_integration() {
    let blockchain_urls = vec![
        "https://matic-mumbai.chainstacklabs.com",
        "https://rpc-mumbai.maticvigil.com",
        "https://matic-testnet-archive-rpc.bwarelabs.com",
    ];
    let chain = Chain::PolyMumbai;

    assert_contract(blockchain_urls, &chain, "tMASQ", 18)
}

#[test]
fn masq_erc20_contract_exists_on_polygon_mainnet_integration() {
    let blockchain_urls = vec!["https://polygon-rpc.com/"];
    let chain = Chain::PolyMainnet;

    assert_contract(blockchain_urls, &chain, "MASQ (PoS)", 18)
}

#[test]
fn masq_erc20_contract_exists_on_ethereum_mainnet_integration() {
    let blockchain_urls = vec!["https://mainnet.infura.io/v3/0ead23143b174f6983c76f69ddcf4026"];
    let chain = Chain::EthMainnet;

    assert_contract(blockchain_urls, &chain, "MASQ", 18)
}

#[test]
fn masq_erc20_contract_exists_on_ethereum_ropsten_integration() {
    let blockchain_urls = vec!["https://ropsten.infura.io/v3/0ead23143b174f6983c76f69ddcf4026"];
    let chain = Chain::EthRopsten;

    assert_contract(blockchain_urls, &chain, "Shroud", 18)
}
