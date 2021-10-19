// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

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
    let mut filtered = collection_of_chains
        .iter()
        .filter(closure)
        .collect::<Vec<&BlockchainRecord>>();
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
