// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::{
    ETH_MAINNET_CONTRACT_ADDRESS, MULTINODE_TESTNET_CONTRACT_ADDRESS,
    MUMBAI_TESTNET_CONTRACT_ADDRESS, POLYGON_MAINNET_CONTRACT_ADDRESS,
    ROPSTEN_TESTNET_CONTRACT_ADDRESS,
};
use itertools::Itertools;
use masq_lib::constants::{
    DEV_CHAIN_IDENTIFIER, ETH_MAINNET_CONTRACT_CREATION_BLOCK, ETH_MAINNET_IDENTIFIER,
    ETH_ROPSTEN_IDENTIFIER, MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
    MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK, POLYGON_MAINNET_CONTRACT_CREATION_BLOCK,
    POLY_MAINNET_IDENTIFIER, POLY_MUMBAI_IDENTIFIER,
    ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
};
use serde_derive::{Deserialize, Serialize};
use std::fmt::Debug;
use web3::types::Address;
pub const DEFAULT_CHAIN: Chain = Chain::EthMainnet;

pub const CENTRAL_DELIMITER: char = '@';
pub const CHAIN_IDENTIFIER_DELIMITER: char = ':';

//chains are ordered by their significance for the community of users (the order reflects in some error or help messages)
pub const CHAINS: [BlockchainRecord; 5] = [
    BlockchainRecord {
        literal_chain_id: Chain::PolyMainnet,
        num_chain_id: 137,
        plain_text_name: "poly-mainnet",
        directory_by_platform: "poly",
        chain_identifier: POLY_MAINNET_IDENTIFIER,
        contract: POLYGON_MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: POLYGON_MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        literal_chain_id: Chain::EthMainnet,
        num_chain_id: 1,
        plain_text_name: "eth-mainnet",
        directory_by_platform: "eth",
        chain_identifier: ETH_MAINNET_IDENTIFIER,
        contract: ETH_MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: ETH_MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        literal_chain_id: Chain::PolyMumbai,
        num_chain_id: 80001,
        plain_text_name: "mumbai",
        directory_by_platform: "poly",
        chain_identifier: POLY_MUMBAI_IDENTIFIER,
        contract: MUMBAI_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        literal_chain_id: Chain::EthRopsten,
        num_chain_id: 3,
        plain_text_name: "ropsten",
        directory_by_platform: "eth",
        chain_identifier: ETH_ROPSTEN_IDENTIFIER,
        contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        literal_chain_id: Chain::Dev,
        num_chain_id: 2,
        plain_text_name: "dev",
        directory_by_platform: "dev",
        chain_identifier: DEV_CHAIN_IDENTIFIER,
        contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
    },
];

#[derive(Debug, PartialEq)]
pub struct BlockchainRecord {
    pub literal_chain_id: Chain,
    pub num_chain_id: u64,
    pub plain_text_name: &'static str,
    pub directory_by_platform: &'static str,
    pub chain_identifier: &'static str,
    pub contract: Address,
    pub contract_creation_block: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Chain {
    EthMainnet,
    EthRopsten,
    PolyMainnet,
    PolyMumbai,
    Dev,
}

impl From<&str> for Chain {
    fn from(str: &str) -> Self {
        match str {
            "poly-mainnet" => Chain::PolyMainnet,
            "eth-mainnet" => Chain::EthMainnet,
            "mumbai" => Chain::PolyMumbai,
            "ropsten" => Chain::EthRopsten,
            "dev" => Chain::Dev,
            _ => DEFAULT_CHAIN,
        }
    }
}

impl Chain {
    pub fn record(&self) -> &BlockchainRecord {
        CHAINS
            .iter()
            .find(|b| &b.literal_chain_id == self)
            .unwrap_or_else(|| panic!("BlockchainRecord for '{:?}' doesn't exist", self))
        //untested panic - but works as expect()
    }
    pub fn from_id(id: u64) -> Chain {
        match id {
            1 => Self::EthMainnet,
            2 => Self::Dev,
            3 => Self::EthRopsten,
            137 => Self::PolyMainnet,
            80001 => Self::PolyMumbai,
            x => panic!("Undefined num id '{}' for ChainRecords", x),
        }
    }
}

pub fn chain_from_chain_identifier_opt(identifier: &str) -> Option<Chain> {
    return_record_opt_standard_impl(Box::new(|b: &&BlockchainRecord| {
        b.chain_identifier == identifier
    }))
    .map(|record| record.literal_chain_id)
}

fn return_record_opt_standard_impl<'a, F>(closure: Box<F>) -> Option<&'a BlockchainRecord>
where
    F: FnMut(&&BlockchainRecord) -> bool,
{
    return_record_opt_body(closure, &CHAINS)
}

fn return_record_opt_body<F>(
    closure: Box<F>,
    collection_of_chains: &[BlockchainRecord],
) -> Option<&BlockchainRecord>
where
    F: FnMut(&&BlockchainRecord) -> bool,
{
    let mut filtered = collection_of_chains.iter().filter(closure).collect_vec();
    filtered.pop().map(|first| {
        if filtered.pop() != None {
            panic!("Not unique identifier used to query a BlockchainRecord")
        } else {
            first
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::{
        MUMBAI_TESTNET_CONTRACT_ADDRESS, POLYGON_MAINNET_CONTRACT_ADDRESS,
    };
    use masq_lib::constants::{
        MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK, POLYGON_MAINNET_CONTRACT_CREATION_BLOCK,
    };
    use std::panic::catch_unwind;

    #[test]
    fn record_returns_correct_blockchain_record() {
        let test_array = [
            assert_returns_correct_record(Chain::EthMainnet, 1),
            assert_returns_correct_record(Chain::Dev, 2),
            assert_returns_correct_record(Chain::EthRopsten, 3),
            assert_returns_correct_record(Chain::PolyMainnet, 137),
            assert_returns_correct_record(Chain::PolyMumbai, 80001),
        ];
        assert_if_exhaustive(&test_array)
    }

    fn assert_returns_correct_record(chain: Chain, expected_id: u64) -> Chain {
        assert_eq!(chain.record().num_chain_id, expected_id);
        chain
    }

    #[test]
    fn from_id_works() {
        let test_array = [
            assert_from_id(1, Chain::EthMainnet),
            assert_from_id(2, Chain::Dev),
            assert_from_id(3, Chain::EthRopsten),
            assert_from_id(137, Chain::PolyMainnet),
            assert_from_id(80001, Chain::PolyMumbai),
        ];
        assert_if_exhaustive(&test_array)
    }

    fn assert_from_id(id: u64, chain: Chain) -> Chain {
        assert_eq!(Chain::from_id(id), chain);
        chain
    }

    #[test]
    fn from_id_panics_on_undefined_ids() {
        let index = (1u64..)
            .find(|num| {
                find_record_opt(&|record: &&BlockchainRecord| record.num_chain_id == *num).is_none()
            })
            .unwrap();
        let caught_panic = catch_unwind(|| {
            Chain::from_id(index);
        })
        .unwrap_err();
        let caught_panic = caught_panic.downcast_ref::<String>().unwrap();
        let expected_panic = format!("Undefined num id '{}' for ChainRecords", index);
        assert_eq!(caught_panic, &expected_panic)
    }

    #[test]
    fn from_str_works() {
        let test_array = [
            assert_from_str(Chain::PolyMainnet),
            assert_from_str(Chain::PolyMumbai),
            assert_from_str(Chain::EthMainnet),
            assert_from_str(Chain::EthRopsten),
            assert_from_str(Chain::Dev),
        ];
        assert_if_exhaustive(&test_array)
    }

    fn assert_from_str(chain: Chain) -> Chain {
        assert_eq!(Chain::from(chain.record().plain_text_name), chain);
        chain
    }

    #[test]
    fn undefined_string_for_chain_type_is_dispatched_to_default_chain() {
        assert_eq!(Chain::from("bitcoin"), DEFAULT_CHAIN)
    }

    #[test]
    #[should_panic(expected = "Not unique identifier used to query a BlockchainRecord")]
    fn return_record_opt_panics_if_more_records_meet_the_condition_from_the_closure() {
        let searched_name = "BruhBruh";
        let mut record_one = make_defaulted_blockchain_record();
        record_one.plain_text_name = searched_name;
        let mut record_two = make_defaulted_blockchain_record();
        record_two.plain_text_name = "Jooodooo";
        let mut record_three = make_defaulted_blockchain_record();
        record_three.plain_text_name = searched_name;
        let collection = [record_one, record_two, record_three];

        let _ = return_record_opt_body(
            Box::new(|b: &&BlockchainRecord| b.plain_text_name == searched_name),
            &collection,
        );
    }

    #[test]
    fn return_record_opt_standard_impl_uses_the_right_collection_of_chains() {
        CHAINS.iter().for_each(|record| {
            assert_eq!(
                record,
                return_record_opt_standard_impl(Box::new(
                    |b: &&BlockchainRecord| b.num_chain_id == record.num_chain_id
                ))
                .unwrap()
            )
        });
    }

    #[test]
    fn chains_are_ordered_by_their_significance_for_users() {
        let test_array = [
            assert_chain_significance(0, Chain::PolyMainnet),
            assert_chain_significance(1, Chain::EthMainnet),
            assert_chain_significance(2, Chain::PolyMumbai),
            assert_chain_significance(3, Chain::EthRopsten),
            assert_chain_significance(4, Chain::Dev),
        ];
        assert_if_exhaustive(&test_array)
    }

    fn assert_chain_significance(idx: usize, chain: Chain) -> Chain {
        assert_eq!(CHAINS[idx].literal_chain_id, chain,"Error at index {}",idx);
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
                literal_chain_id: examined_chain,
                plain_text_name: "eth-mainnet",
                directory_by_platform: "eth",
                chain_identifier: "eth-mainnet",
                contract: ETH_MAINNET_CONTRACT_ADDRESS,
                contract_creation_block: ETH_MAINNET_CONTRACT_CREATION_BLOCK,
            }
        )
    }

    #[test]
    fn multinode_testnet_chain_record_is_properly_declared() {
        let examined_chain = Chain::Dev;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 2,
                literal_chain_id: examined_chain,
                plain_text_name: "dev",
                directory_by_platform: "dev",
                chain_identifier: "dev",
                contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: 0
            }
        )
    }

    #[test]
    fn ropsten_record_is_properly_declared() {
        let examined_chain = Chain::EthRopsten;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 3,
                literal_chain_id: examined_chain,
                plain_text_name: "ropsten",
                directory_by_platform: "eth",
                chain_identifier: "eth-ropsten",
                contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
            }
        )
    }

    #[test]
    fn polygon_mainnet_record_is_properly_declared() {
        let examined_chain = Chain::PolyMainnet;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 137,
                literal_chain_id: examined_chain,
                plain_text_name: "poly-mainnet",
                directory_by_platform: "poly",
                chain_identifier: "poly-mainnet",
                contract: POLYGON_MAINNET_CONTRACT_ADDRESS,
                contract_creation_block: POLYGON_MAINNET_CONTRACT_CREATION_BLOCK
            }
        )
    }

    #[test]
    fn mumbai_record_is_properly_declared() {
        let examined_chain = Chain::PolyMumbai;
        let chain_record = return_examined(examined_chain);
        assert_eq!(
            chain_record,
            &BlockchainRecord {
                num_chain_id: 80001,
                literal_chain_id: examined_chain,
                plain_text_name: "mumbai",
                directory_by_platform: "poly",
                chain_identifier: "poly-mumbai",
                contract: MUMBAI_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK
            }
        )
    }

    fn return_examined<'a>(chain: Chain) -> &'a BlockchainRecord {
        find_record_opt(&|blockchain_record| blockchain_record.literal_chain_id == chain).unwrap()
    }

    #[test]
    fn chain_from_chain_identifier_opt_works() {
        let test_array = [
            assert_chain_from_chain_identifier_opt("eth-mainnet", Some(Chain::EthMainnet)),
            assert_chain_from_chain_identifier_opt("eth-ropsten", Some(Chain::EthRopsten)),
            assert_chain_from_chain_identifier_opt("dev", Some(Chain::Dev)),
            assert_chain_from_chain_identifier_opt("poly-mainnet", Some(Chain::PolyMainnet)),
            assert_chain_from_chain_identifier_opt("poly-mumbai", Some(Chain::PolyMumbai)),
        ];
        assert_eq!(
            test_array.len(),
            CHAINS.len(),
            "More chain records than assertions"
        )
    }

    #[test]
    fn chain_from_chain_identifier_returns_none_if_unknown_identifier() {
        assert_chain_from_chain_identifier_opt("bitcoin", None)
    }

    fn assert_chain_from_chain_identifier_opt(
        identifier: &str,
        expected_blockchain: Option<Chain>,
    ) {
        assert_eq!(
            chain_from_chain_identifier_opt(identifier),
            expected_blockchain
        )
    }

    fn find_record_opt(
        closure: &dyn Fn(&&BlockchainRecord) -> bool,
    ) -> Option<&'static BlockchainRecord> {
        CHAINS.iter().find(closure)
    }

    fn assert_if_exhaustive(test_array: &[Chain]) {
        let test_array_length = test_array.len();
        let chains_length = CHAINS.len();
        assert_eq!(
            test_array_length, chains_length,
            "Tested chains in total: {}, defined chains in total: {}",
            test_array_length, chains_length
        );
        let init = (None, None);
        CHAINS.iter().for_each(|chain_record| {
            let found = test_array.iter()
                .fold(init, |so_far, chain| match so_far {
                (Some(chain_found), None) => (Some(chain_found), None),
                (None, _) => match *chain == chain_record.literal_chain_id {
                    true => (Some(chain), None),
                    false => (None, Some(chain)),
                },
                x => panic!("Should not happen!: {:?}", x),
            });
            assert!(
                found.0.is_some(),
                "Assertion for '{:?}' is missing",
                found.1.unwrap()
            )
        })
    }

    fn make_defaulted_blockchain_record() -> BlockchainRecord {
        BlockchainRecord {
            num_chain_id: 0,
            literal_chain_id: Chain::EthMainnet,
            plain_text_name: "",
            directory_by_platform: "",
            chain_identifier: "",
            contract: Default::default(),
            contract_creation_block: 0,
        }
    }
}
