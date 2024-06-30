// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use crate::constants::{
    AMOY_TESTNET_CONTRACT_CREATION_BLOCK, DEV_CHAIN_FULL_IDENTIFIER,
    ETH_MAINNET_CONTRACT_CREATION_BLOCK, ETH_MAINNET_FULL_IDENTIFIER, ETH_ROPSTEN_FULL_IDENTIFIER,
    MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK, POLYGON_AMOY_FULL_IDENTIFIER,
    POLYGON_MAINNET_CONTRACT_CREATION_BLOCK, POLYGON_MAINNET_FULL_IDENTIFIER,
    ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
};
use ethereum_types::{Address, H160};

pub const CHAINS: [BlockchainRecord; 5] = [
    BlockchainRecord {
        self_id: Chain::PolyMainnet,
        num_chain_id: 137,
        literal_identifier: POLYGON_MAINNET_FULL_IDENTIFIER,
        contract: POLYGON_MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: POLYGON_MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::EthMainnet,
        num_chain_id: 1,
        literal_identifier: ETH_MAINNET_FULL_IDENTIFIER,
        contract: ETH_MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: ETH_MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::PolyAmoy,
        num_chain_id: 80002,
        literal_identifier: POLYGON_AMOY_FULL_IDENTIFIER,
        contract: AMOY_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: AMOY_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::EthRopsten,
        num_chain_id: 3,
        literal_identifier: ETH_ROPSTEN_FULL_IDENTIFIER,
        contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::Dev,
        num_chain_id: 2,
        literal_identifier: DEV_CHAIN_FULL_IDENTIFIER,
        contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
    },
];

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct BlockchainRecord {
    pub self_id: Chain,
    pub num_chain_id: u64,
    pub literal_identifier: &'static str,
    pub contract: Address,
    pub contract_creation_block: u64,
}

const POLYGON_MAINNET_CONTRACT_ADDRESS: Address = H160([
    0xee, 0x9a, 0x35, 0x2f, 0x6a, 0xac, 0x4a, 0xf1, 0xa5, 0xb9, 0xf4, 0x67, 0xf6, 0xa9, 0x3e, 0x0f,
    0xfb, 0xe9, 0xdd, 0x35,
]);

const ETH_MAINNET_CONTRACT_ADDRESS: Address = H160([
    0x06, 0xf3, 0xc3, 0x23, 0xf0, 0x23, 0x8c, 0x72, 0xbf, 0x35, 0x01, 0x10, 0x71, 0xf2, 0xb5, 0xb7,
    0xf4, 0x3a, 0x05, 0x4c,
]);

// $tMASQ (Amoy)
const AMOY_TESTNET_CONTRACT_ADDRESS: Address = H160([
    0xd9, 0x8c, 0x3e, 0xbd, 0x6b, 0x7f, 0x9b, 0x7c, 0xda, 0x24, 0x49, 0xec, 0xac, 0x00, 0xd1, 0xe5,
    0xf4, 0x7a, 0x81, 0x93,
]);

// SHRD (Ropsten)
const ROPSTEN_TESTNET_CONTRACT_ADDRESS: Address = H160([
    0x38, 0x4d, 0xec, 0x25, 0xe0, 0x3f, 0x94, 0x93, 0x17, 0x67, 0xce, 0x4c, 0x35, 0x56, 0x16, 0x84,
    0x68, 0xba, 0x24, 0xc3,
]);

const MULTINODE_TESTNET_CONTRACT_ADDRESS: Address = H160([
    0x59, 0x88, 0x2e, 0x4a, 0x8f, 0x5d, 0x24, 0x64, 0x3d, 0x4d, 0xda, 0x42, 0x29, 0x22, 0xa8, 0x70,
    0xf1, 0xb3, 0xe6, 0x64,
]);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchains::chains::chain_from_chain_identifier_opt;
    use crate::constants::{
        AMOY_TESTNET_CONTRACT_CREATION_BLOCK, POLYGON_MAINNET_CONTRACT_CREATION_BLOCK,
    };
    use std::collections::HashSet;
    use std::iter::FromIterator;

    #[test]
    fn record_returns_correct_blockchain_record() {
        let test_array = [
            assert_returns_correct_record(Chain::EthMainnet, 1),
            assert_returns_correct_record(Chain::Dev, 2),
            assert_returns_correct_record(Chain::EthRopsten, 3),
            assert_returns_correct_record(Chain::PolyMainnet, 137),
            assert_returns_correct_record(Chain::PolyAmoy, 80002),
        ];
        assert_exhaustive(&test_array)
    }

    fn assert_returns_correct_record(chain: Chain, expected_id: u64) -> Chain {
        assert_eq!(chain.rec().num_chain_id, expected_id);
        chain
    }

    #[test]
    fn from_str_works() {
        let test_array = [
            assert_from_str(Chain::PolyMainnet),
            assert_from_str(Chain::PolyAmoy),
            assert_from_str(Chain::EthMainnet),
            assert_from_str(Chain::EthRopsten),
            assert_from_str(Chain::Dev),
        ];
        assert_exhaustive(&test_array)
    }

    fn assert_from_str(chain: Chain) -> Chain {
        assert_eq!(Chain::from(chain.rec().literal_identifier), chain);
        chain
    }

    #[test]
    #[should_panic(expected = "Clap let in a wrong value for chain: 'bitcoin'")]
    fn undefined_str_causes_a_panic() {
        let _ = Chain::from("bitcoin");
    }

    #[test]
    fn chains_are_ordered_by_their_significance_for_users() {
        let test_array = [
            assert_chain_significance(0, Chain::PolyMainnet),
            assert_chain_significance(1, Chain::EthMainnet),
            assert_chain_significance(2, Chain::PolyAmoy),
            assert_chain_significance(3, Chain::EthRopsten),
            assert_chain_significance(4, Chain::Dev),
        ];
        assert_exhaustive(&test_array)
    }

    fn assert_chain_significance(idx: usize, chain: Chain) -> Chain {
        assert_eq!(CHAINS[idx].self_id, chain, "Error at index {}", idx);
        chain
    }

    #[test]
    fn eth_mainnet_record_is_properly_declared() {
        let examined_chain = Chain::EthMainnet;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 1,
                self_id: examined_chain,
                literal_identifier: "eth-mainnet",
                contract: ETH_MAINNET_CONTRACT_ADDRESS,
                contract_creation_block: ETH_MAINNET_CONTRACT_CREATION_BLOCK,
            }
        );
    }

    #[test]
    fn ropsten_record_is_properly_declared() {
        let examined_chain = Chain::EthRopsten;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 3,
                self_id: examined_chain,
                literal_identifier: "eth-ropsten",
                contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
            }
        );
    }

    #[test]
    fn polygon_mainnet_record_is_properly_declared() {
        let examined_chain = Chain::PolyMainnet;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 137,
                self_id: examined_chain,
                literal_identifier: "polygon-mainnet",
                contract: POLYGON_MAINNET_CONTRACT_ADDRESS,
                contract_creation_block: POLYGON_MAINNET_CONTRACT_CREATION_BLOCK,
            }
        );
    }

    #[test]
    fn amoy_record_is_properly_declared() {
        let examined_chain = Chain::PolyAmoy;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 80002,
                self_id: examined_chain,
                literal_identifier: "polygon-amoy",
                contract: AMOY_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: AMOY_TESTNET_CONTRACT_CREATION_BLOCK,
            }
        );
    }

    #[test]
    fn multinode_testnet_chain_record_is_properly_declared() {
        let examined_chain = Chain::Dev;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 2,
                self_id: examined_chain,
                literal_identifier: "dev",
                contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: 0,
            }
        );
    }

    fn return_examined<'a>(chain: Chain) -> &'a BlockchainRecord {
        find_record_opt(&|blockchain_record| blockchain_record.self_id == chain).unwrap()
    }

    #[test]
    fn chain_from_chain_identifier_opt_works() {
        let test_array = [
            assert_chain_from_chain_identifier_opt("eth-mainnet", Some(Chain::EthMainnet)),
            assert_chain_from_chain_identifier_opt("eth-ropsten", Some(Chain::EthRopsten)),
            assert_chain_from_chain_identifier_opt("dev", Some(Chain::Dev)),
            assert_chain_from_chain_identifier_opt("polygon-mainnet", Some(Chain::PolyMainnet)),
            assert_chain_from_chain_identifier_opt("polygon-amoy", Some(Chain::PolyAmoy)),
        ];
        assert_exhaustive(&test_array)
    }

    #[test]
    fn chain_from_chain_identifier_returns_none_if_unknown_identifier() {
        assert_eq!(chain_from_chain_identifier_opt("bitcoin"), None)
    }

    fn assert_chain_from_chain_identifier_opt(
        identifier: &str,
        expected_blockchain: Option<Chain>,
    ) -> Chain {
        assert_eq!(
            chain_from_chain_identifier_opt(identifier),
            expected_blockchain
        );
        expected_blockchain.unwrap()
    }

    fn find_record_opt(
        closure: &dyn Fn(&&BlockchainRecord) -> bool,
    ) -> Option<&'static BlockchainRecord> {
        CHAINS.iter().find(closure)
    }

    fn assert_exhaustive(test_array: &[Chain]) {
        let full_set: HashSet<&Chain> =
            HashSet::from_iter(CHAINS.iter().map(|record| &record.self_id));
        let test_array_set = HashSet::from_iter(test_array.iter());
        let diff = full_set.difference(&test_array_set).collect::<Vec<_>>();
        assert!(
            diff.is_empty(),
            "These chains weren't included in the test: {:?}",
            diff
        )
    }
}
