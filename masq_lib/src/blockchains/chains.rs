// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::blockchain_records::{BlockchainRecord, CHAINS};
use crate::constants::{
    DEFAULT_CHAIN, DEV_CHAIN_FULL_IDENTIFIER, ETH_MAINNET_FULL_IDENTIFIER,
    ETH_ROPSTEN_FULL_IDENTIFIER, POLYGON_MAINNET_FULL_IDENTIFIER, POLYGON_AMOY_FULL_IDENTIFIER
};
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Chain {
    EthMainnet,
    EthRopsten,
    PolyMainnet,
    PolyAmoy,
    Dev,
}

impl Default for Chain {
    fn default() -> Self {
        DEFAULT_CHAIN
    }
}

impl From<&str> for Chain {
    fn from(str: &str) -> Self {
        if str == POLYGON_MAINNET_FULL_IDENTIFIER {
            Chain::PolyMainnet
        } else if str == ETH_MAINNET_FULL_IDENTIFIER {
            Chain::EthMainnet
        } else if str == POLYGON_AMOY_FULL_IDENTIFIER {
            Chain::PolyAmoy
        } else if str == ETH_ROPSTEN_FULL_IDENTIFIER {
            Chain::EthRopsten
        } else if str == DEV_CHAIN_FULL_IDENTIFIER {
            Chain::Dev
        } else {
            panic!("Clap let in a wrong value for chain: '{}'; if this happens we need to track down the slit", str)
        }
    }
}

impl Chain {
    pub fn rec(&self) -> &BlockchainRecord {
        CHAINS
            .iter()
            .find(|b| &b.self_id == self)
            .unwrap_or_else(|| panic!("BlockchainRecord for '{:?}' doesn't exist", self))
        //untested panic - but works as an expect()
    }

    pub fn is_mainnet(&self) -> bool {
        Self::mainnets()
            .iter()
            .any(|mainnet_chain| mainnet_chain == self)
    }

    fn mainnets() -> &'static [Chain] {
        &[Chain::PolyMainnet, Chain::EthMainnet]
    }
}

pub fn chain_from_chain_identifier_opt(identifier: &str) -> Option<Chain> {
    return_record_opt_standard_impl(&|b: &&BlockchainRecord| b.literal_identifier == identifier)
        .map(|record| record.self_id)
}

fn return_record_opt_standard_impl(
    closure: &dyn Fn(&&BlockchainRecord) -> bool,
) -> Option<&BlockchainRecord> {
    return_record_opt_body(closure, &CHAINS)
}

fn return_record_opt_body<'a>(
    closure: &dyn Fn(&&'a BlockchainRecord) -> bool,
    collection_of_chains: &'a [BlockchainRecord],
) -> Option<&'a BlockchainRecord> {
    let filtered = collection_of_chains
        .iter()
        .filter(closure)
        .collect::<Vec<&BlockchainRecord>>();
    match filtered.len() {
        0 => None,
        1 => Some(filtered[0]),
        _ => panic!("Non-unique identifier used to query a BlockchainRecord"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Non-unique identifier used to query a BlockchainRecord")]
    fn return_record_opt_panics_if_more_records_meet_the_condition_from_the_closure() {
        let searched_name = "BruhBruh";
        let mut record_one = make_defaulted_blockchain_record();
        record_one.literal_identifier = searched_name;
        let mut record_two = make_defaulted_blockchain_record();
        record_two.literal_identifier = "Jooodooo";
        let mut record_three = make_defaulted_blockchain_record();
        record_three.literal_identifier = searched_name;
        let collection = [record_one, record_two, record_three];

        let _ = return_record_opt_body(
            &|b: &&BlockchainRecord| b.literal_identifier == searched_name,
            &collection,
        );
    }

    #[test]
    fn return_record_opt_standard_impl_uses_the_right_collection_of_chains() {
        CHAINS.iter().for_each(|record| {
            assert_eq!(
                record,
                return_record_opt_standard_impl(
                    &|b: &&BlockchainRecord| b.num_chain_id == record.num_chain_id
                )
                .unwrap()
            )
        });
    }

    #[test]
    #[should_panic(
        expected = "Clap let in a wrong value for chain: 'olala'; if this happens we need to track down the slit"
    )]
    fn gibberish_causes_a_panic() {
        let _ = Chain::from("olala");
    }

    fn make_defaulted_blockchain_record<'a>() -> BlockchainRecord {
        BlockchainRecord {
            num_chain_id: 0,
            self_id: Chain::PolyMainnet,
            literal_identifier: "",
            contract: Default::default(),
            contract_creation_block: 0,
        }
    }

    #[test]
    fn is_mainnet_knows_about_all_mainnets() {
        let searched_str = "mainnet";
        assert_mainnet_exist();
        CHAINS.iter().for_each(|blockchain_record| {
            if blockchain_record.literal_identifier.contains(searched_str) {
                let chain = blockchain_record.self_id;
                assert_eq!(chain.is_mainnet(), true)
            }
        })
    }

    fn assert_mainnet_exist() {
        assert!(CHAINS
            .iter()
            .find(|blockchain_record| blockchain_record.literal_identifier.contains("mainnet"))
            .is_some());
    }
}
