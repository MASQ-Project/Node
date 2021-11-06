// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::blockchain_records::{BlockchainRecord, CHAINS};
use crate::constants::DEFAULT_CHAIN;
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Chain {
    EthMainnet,
    EthRopsten,
    PolyMainnet,
    PolyMumbai,
    Dev,
}

impl Default for Chain {
    fn default() -> Self {
        DEFAULT_CHAIN
    }
}

impl From<&str> for Chain {
    fn from(str: &str) -> Self {
        match str {
            "polygon-mainnet" => Chain::PolyMainnet,
            "eth-mainnet" => Chain::EthMainnet,
            "mumbai" => Chain::PolyMumbai,
            "ropsten" => Chain::EthRopsten,
            "dev" => Chain::Dev,
            x => panic!("Clap let in a wrong value for chain: '{}'; if this happens we need to track down the slit", x),
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
}

pub fn chain_from_chain_identifier_opt(identifier: &str) -> Option<Chain> {
    return_record_opt_standard_impl(&|b: &&BlockchainRecord| b.descriptor_identifier == identifier)
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
    use crate::shared_schema::official_chain_names;

    #[test]
    #[should_panic(expected = "Non-unique identifier used to query a BlockchainRecord")]
    fn return_record_opt_panics_if_more_records_meet_the_condition_from_the_closure() {
        let searched_name = "BruhBruh";
        let mut record_one = make_defaulted_blockchain_record();
        record_one.commandline_name = searched_name;
        let mut record_two = make_defaulted_blockchain_record();
        record_two.commandline_name = "Jooodooo";
        let mut record_three = make_defaulted_blockchain_record();
        record_three.commandline_name = searched_name;
        let collection = [record_one, record_two, record_three];

        let _ = return_record_opt_body(
            &|b: &&BlockchainRecord| b.commandline_name == searched_name,
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
    fn chain_from_str_works_reliably() {
        let mut iterator = official_chain_names().iter();
        assert_eq!(Chain::from(*iterator.next().unwrap()), Chain::PolyMainnet);
        assert_eq!(Chain::from(*iterator.next().unwrap()), Chain::EthMainnet);
        assert_eq!(Chain::from(*iterator.next().unwrap()), Chain::PolyMumbai);
        assert_eq!(Chain::from(*iterator.next().unwrap()), Chain::EthRopsten);
        assert_eq!(Chain::from(*iterator.next().unwrap()), Chain::Dev);
        assert_eq!(iterator.next(), None)
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
            self_id: Chain::EthMainnet,
            commandline_name: "",
            family_directory: "",
            descriptor_identifier: "",
            contract: Default::default(),
            contract_creation_block: 0,
        }
    }
}
