// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde_derive::{Deserialize, Serialize};
use crate::blockchains::blockchain_records::{BlockchainRecord, CHAINS};
use crate::constants::DEFAULT_CHAIN;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Chain {
    EthMainnet,
    EthRopsten,
    PolyMainnet,
    PolyMumbai,
    Dev,
}

impl Default for Chain{
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
    let mut filtered = collection_of_chains
        .iter().filter(closure).collect::<Vec<&BlockchainRecord>>();
    filtered.pop().map(|first| {
        if filtered.pop() != None {
            panic!("Not unique identifier used to query a BlockchainRecord")
        } else {
            first
        }
    })
}

#[cfg(test)]
mod tests{
    use super::*;
    use std::panic::catch_unwind;

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
}