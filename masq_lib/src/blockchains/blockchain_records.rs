// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use crate::constants::{
    BASE_GAS_PRICE_CEILING_WEI, BASE_MAINNET_CHAIN_ID, BASE_MAINNET_CONTRACT_CREATION_BLOCK,
    BASE_MAINNET_FULL_IDENTIFIER, BASE_SEPOLIA_CHAIN_ID, BASE_SEPOLIA_CONTRACT_CREATION_BLOCK,
    BASE_SEPOLIA_FULL_IDENTIFIER, DEFAULT_PENDING_PAYABLE_INTERVAL_BASE_SEC,
    DEFAULT_PENDING_PAYABLE_INTERVAL_DEV_SEC, DEFAULT_PENDING_PAYABLE_INTERVAL_ETH_SEC,
    DEFAULT_PENDING_PAYABLE_INTERVAL_POLYGON_SEC, DEV_CHAIN_FULL_IDENTIFIER, DEV_CHAIN_ID,
    DEV_GAS_PRICE_CEILING_WEI, ETH_GAS_PRICE_CEILING_WEI, ETH_MAINNET_CHAIN_ID,
    ETH_MAINNET_CONTRACT_CREATION_BLOCK, ETH_MAINNET_FULL_IDENTIFIER, ETH_ROPSTEN_CHAIN_ID,
    ETH_ROPSTEN_CONTRACT_CREATION_BLOCK, ETH_ROPSTEN_FULL_IDENTIFIER,
    MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK, POLYGON_AMOY_CHAIN_ID,
    POLYGON_AMOY_CONTRACT_CREATION_BLOCK, POLYGON_AMOY_FULL_IDENTIFIER,
    POLYGON_GAS_PRICE_CEILING_WEI, POLYGON_MAINNET_CHAIN_ID,
    POLYGON_MAINNET_CONTRACT_CREATION_BLOCK, POLYGON_MAINNET_FULL_IDENTIFIER,
};
use ethereum_types::{Address, H160};

pub static CHAINS: [BlockchainRecord; 7] = [
    BlockchainRecord {
        self_id: Chain::PolyMainnet,
        num_chain_id: POLYGON_MAINNET_CHAIN_ID,
        literal_identifier: POLYGON_MAINNET_FULL_IDENTIFIER,
        gas_price_safe_ceiling_minor: POLYGON_GAS_PRICE_CEILING_WEI,
        default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_POLYGON_SEC,
        contract: POLYGON_MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: POLYGON_MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::EthMainnet,
        num_chain_id: ETH_MAINNET_CHAIN_ID,
        literal_identifier: ETH_MAINNET_FULL_IDENTIFIER,
        gas_price_safe_ceiling_minor: ETH_GAS_PRICE_CEILING_WEI,
        default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_ETH_SEC,
        contract: ETH_MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: ETH_MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::BaseMainnet,
        num_chain_id: BASE_MAINNET_CHAIN_ID,
        literal_identifier: BASE_MAINNET_FULL_IDENTIFIER,
        gas_price_safe_ceiling_minor: BASE_GAS_PRICE_CEILING_WEI,
        default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_BASE_SEC,
        contract: BASE_MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: BASE_MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::BaseSepolia,
        num_chain_id: BASE_SEPOLIA_CHAIN_ID,
        literal_identifier: BASE_SEPOLIA_FULL_IDENTIFIER,
        gas_price_safe_ceiling_minor: BASE_GAS_PRICE_CEILING_WEI,
        default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_BASE_SEC,
        contract: BASE_SEPOLIA_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: BASE_SEPOLIA_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::PolyAmoy,
        num_chain_id: POLYGON_AMOY_CHAIN_ID,
        literal_identifier: POLYGON_AMOY_FULL_IDENTIFIER,
        gas_price_safe_ceiling_minor: POLYGON_GAS_PRICE_CEILING_WEI,
        default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_POLYGON_SEC,
        contract: POLYGON_AMOY_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: POLYGON_AMOY_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::EthRopsten,
        num_chain_id: ETH_ROPSTEN_CHAIN_ID,
        literal_identifier: ETH_ROPSTEN_FULL_IDENTIFIER,
        gas_price_safe_ceiling_minor: ETH_GAS_PRICE_CEILING_WEI,
        default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_ETH_SEC,
        contract: ETH_ROPSTEN_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: ETH_ROPSTEN_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        self_id: Chain::Dev,
        num_chain_id: DEV_CHAIN_ID,
        literal_identifier: DEV_CHAIN_FULL_IDENTIFIER,
        gas_price_safe_ceiling_minor: DEV_GAS_PRICE_CEILING_WEI,
        default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_DEV_SEC,
        contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
    },
];

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct BlockchainRecord {
    pub self_id: Chain,
    pub num_chain_id: u64,
    pub literal_identifier: &'static str,
    pub gas_price_safe_ceiling_minor: u128,
    pub default_pending_payable_interval_sec: u64,
    pub contract: Address,
    pub contract_creation_block: u64,
}

// $tMASQ (Amoy)
const POLYGON_AMOY_TESTNET_CONTRACT_ADDRESS: Address = H160([
    0xd9, 0x8c, 0x3e, 0xbd, 0x6b, 0x7f, 0x9b, 0x7c, 0xda, 0x24, 0x49, 0xec, 0xac, 0x00, 0xd1, 0xe5,
    0xf4, 0x7a, 0x81, 0x93,
]);

// SHRD (Ropsten)
const ETH_ROPSTEN_TESTNET_CONTRACT_ADDRESS: Address = H160([
    0x38, 0x4d, 0xec, 0x25, 0xe0, 0x3f, 0x94, 0x93, 0x17, 0x67, 0xce, 0x4c, 0x35, 0x56, 0x16, 0x84,
    0x68, 0xba, 0x24, 0xc3,
]);

const BASE_MAINNET_CONTRACT_ADDRESS: Address = H160([
    0x45, 0xD9, 0xC1, 0x01, 0xa3, 0x87, 0x0C, 0xa5, 0x02, 0x45, 0x82, 0xfd, 0x78, 0x8F, 0x4E, 0x1e,
    0x8F, 0x79, 0x71, 0xc3,
]);

const BASE_SEPOLIA_TESTNET_CONTRACT_ADDRESS: Address = H160([
    0x89, 0x8e, 0x1c, 0xe7, 0x20, 0x08, 0x4A, 0x90, 0x2b, 0xc3, 0x7d, 0xd8, 0x22, 0xed, 0x6d, 0x6a,
    0x5f, 0x02, 0x7e, 0x10,
]);

const MULTINODE_TESTNET_CONTRACT_ADDRESS: Address = H160([
    0x59, 0x88, 0x2e, 0x4a, 0x8f, 0x5d, 0x24, 0x64, 0x3d, 0x4d, 0xda, 0x42, 0x29, 0x22, 0xa8, 0x70,
    0xf1, 0xb3, 0xe6, 0x64,
]);

const ETH_MAINNET_CONTRACT_ADDRESS: Address = H160([
    0x06, 0xF3, 0xC3, 0x23, 0xf0, 0x23, 0x8c, 0x72, 0xBF, 0x35, 0x01, 0x10, 0x71, 0xf2, 0xb5, 0xB7,
    0xF4, 0x3A, 0x05, 0x4c,
]);

#[allow(clippy::mixed_case_hex_literals)]
const POLYGON_MAINNET_CONTRACT_ADDRESS: Address = H160([
    0xEe, 0x9A, 0x35, 0x2F, 0x6a, 0xAc, 0x4a, 0xF1, 0xA5, 0xB9, 0xf4, 0x67, 0xF6, 0xa9, 0x3E, 0x0f,
    0xfB, 0xe9, 0xDd, 0x35,
]);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchains::chains::chain_from_chain_identifier_opt;
    use crate::constants::{
        BASE_MAINNET_CONTRACT_CREATION_BLOCK, DEFAULT_PENDING_PAYABLE_INTERVAL_BASE_SEC,
        DEFAULT_PENDING_PAYABLE_INTERVAL_DEV_SEC, DEFAULT_PENDING_PAYABLE_INTERVAL_ETH_SEC,
        DEFAULT_PENDING_PAYABLE_INTERVAL_POLYGON_SEC, WEIS_IN_GWEI,
    };
    use std::collections::HashSet;
    use std::iter::FromIterator;

    #[test]
    fn record_returns_correct_blockchain_record() {
        let test_array = [
            assert_returns_correct_record(Chain::EthMainnet, 1),
            assert_returns_correct_record(Chain::EthRopsten, 3),
            assert_returns_correct_record(Chain::PolyMainnet, 137),
            assert_returns_correct_record(Chain::PolyAmoy, 80002),
            assert_returns_correct_record(Chain::BaseMainnet, 8453),
            assert_returns_correct_record(Chain::BaseSepolia, 84532),
            assert_returns_correct_record(Chain::Dev, 2),
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
            assert_from_str(Chain::BaseMainnet),
            assert_from_str(Chain::BaseSepolia),
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
            Chain::PolyMainnet,
            Chain::EthMainnet,
            Chain::BaseMainnet,
            Chain::BaseSepolia,
            Chain::PolyAmoy,
            Chain::EthRopsten,
            Chain::Dev,
        ];
        test_array
            .iter()
            .enumerate()
            .for_each(assert_chain_significance);
        assert_exhaustive(&test_array)
    }

    fn assert_chain_significance((idx, chain): (usize, &Chain)) {
        assert_eq!(CHAINS[idx].self_id, *chain, "Error at index {}", idx);
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
                gas_price_safe_ceiling_minor: 100 * WEIS_IN_GWEI as u128,
                default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_ETH_SEC,
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
                gas_price_safe_ceiling_minor: 100 * WEIS_IN_GWEI as u128,
                default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_ETH_SEC,
                contract: ETH_ROPSTEN_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: ETH_ROPSTEN_CONTRACT_CREATION_BLOCK,
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
                gas_price_safe_ceiling_minor: 200 * WEIS_IN_GWEI as u128,
                default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_POLYGON_SEC,
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
                gas_price_safe_ceiling_minor: 200 * WEIS_IN_GWEI as u128,
                default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_POLYGON_SEC,
                contract: POLYGON_AMOY_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: POLYGON_AMOY_CONTRACT_CREATION_BLOCK,
            }
        );
    }

    #[test]
    fn base_mainnet_record_is_properly_declared() {
        let examined_chain = Chain::BaseMainnet;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 8453,
                self_id: examined_chain,
                literal_identifier: "base-mainnet",
                gas_price_safe_ceiling_minor: 50 * WEIS_IN_GWEI as u128,
                default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_BASE_SEC,
                contract: BASE_MAINNET_CONTRACT_ADDRESS,
                contract_creation_block: BASE_MAINNET_CONTRACT_CREATION_BLOCK,
            }
        );
    }

    #[test]
    fn base_sepolia_record_is_properly_declared() {
        let examined_chain = Chain::BaseSepolia;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 84532,
                self_id: examined_chain,
                literal_identifier: "base-sepolia",
                gas_price_safe_ceiling_minor: 50 * WEIS_IN_GWEI as u128,
                default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_BASE_SEC,
                contract: BASE_SEPOLIA_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: BASE_SEPOLIA_CONTRACT_CREATION_BLOCK,
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
                gas_price_safe_ceiling_minor: 200 * WEIS_IN_GWEI as u128,
                default_pending_payable_interval_sec: DEFAULT_PENDING_PAYABLE_INTERVAL_DEV_SEC,
                contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
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
            assert_chain_from_chain_identifier_opt("polygon-mainnet", Some(Chain::PolyMainnet)),
            assert_chain_from_chain_identifier_opt("polygon-amoy", Some(Chain::PolyAmoy)),
            assert_chain_from_chain_identifier_opt("base-mainnet", Some(Chain::BaseMainnet)),
            assert_chain_from_chain_identifier_opt("base-sepolia", Some(Chain::BaseSepolia)),
            assert_chain_from_chain_identifier_opt("dev", Some(Chain::Dev)),
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
