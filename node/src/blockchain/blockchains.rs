// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::{
    MAINNET_CONTRACT_ADDRESS, MULTINODE_TESTNET_CONTRACT_ADDRESS, RINKEBY_TESTNET_CONTRACT_ADDRESS,
    ROPSTEN_TESTNET_CONTRACT_ADDRESS,
};
use crate::sub_lib::neighborhood::Blockchain;
use masq_lib::constants::{DEV_LABEL, ETH_MAINNET_LABEL, ETH_RINKEBY_LABEL, ETH_ROPSTEN_LABEL, MAINNET_CONTRACT_CREATION_BLOCK, ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK, RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK, MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK};
use web3::types::Address;

use std::fmt::Debug;
use itertools::Itertools;

pub const KEY_VS_IP_DELIMITER: char = ':';
pub const CHAIN_LABEL_DELIMITER: char = '.';

pub const CHAINS: [BlockchainRecord; 4] = [
    BlockchainRecord {
        num_chain_id: 1,
        literal_chain_id: Blockchain::EthMainnet,
        in_command_name: "eth-mainnet",
        directory_by_platform: "eth",
        chain_label: ETH_MAINNET_LABEL,
        contract: MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 3,
        literal_chain_id: Blockchain::EthRopsten,
        in_command_name: "ropsten",
        directory_by_platform: "eth",
        chain_label: ETH_ROPSTEN_LABEL,
        contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 4,
        literal_chain_id: Blockchain::EthRinkeby,
        in_command_name: "rinkeby",
        directory_by_platform: "eth",
        chain_label: ETH_RINKEBY_LABEL,
        contract: RINKEBY_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 5,
        literal_chain_id: Blockchain::Dev,
        in_command_name: "dev",
        directory_by_platform: "dev",
        chain_label: DEV_LABEL,
        contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
    },
];

#[derive(Debug, PartialEq)]
pub struct BlockchainRecord {
    pub num_chain_id: u8,
    pub literal_chain_id: Blockchain,
    pub in_command_name: &'static str,
    pub directory_by_platform: &'static str,
    pub chain_label: &'static str,
    pub contract: Address,
    pub contract_creation_block: u64,
}

pub fn contract_address(chain_id: u8) -> Address {
    return_record_by_chain_id(chain_id).contract
}

pub fn contract_creation_block_from_chain_id(chain_id: u8) -> u64 {
    return_record_by_chain_id(chain_id).contract_creation_block
}

pub fn chain_name_from_id(chain_id: u8) -> &'static str {
    return_record_by_chain_id(chain_id).in_command_name
}

pub fn chain_name_from_blockchain(blockchain_name: Blockchain) -> &'static str {
    chain_name_from_id(chain_id_from_blockchain(blockchain_name))
}

pub fn chain_id_from_blockchain(blockchain: Blockchain) -> u8 {
    return_record_by_blockchain_name(blockchain).num_chain_id
}

pub fn chain_id_from_name(chain_name: &str) -> u8 {
    return_record_by_chain_name(chain_name).num_chain_id
}

pub fn blockchain_from_chain_id(chain_id: u8) -> Blockchain {
    return_record_by_chain_id(chain_id).literal_chain_id
}

pub fn platform_from_chain_name(chain_name: &str) -> &str {
    return_record_by_chain_name(chain_name).directory_by_platform
}

pub fn label_from_blockchain(blockchain: Blockchain) -> &'static str {
    return_record_by_blockchain_name(blockchain).chain_label
}

pub fn blockchain_from_label_opt(label: &str) -> Option<Blockchain> {
    return_record_opt_standard_impl(Box::new(|b: &&BlockchainRecord| b.chain_label == label))
        .map(|record| record.literal_chain_id)
}

#[track_caller]
fn return_record<F>(closure: Box<F>) -> &'static BlockchainRecord
    where
        F: FnMut(&&BlockchainRecord) -> bool,
{
    return_record_opt_standard_impl(closure).expect("chain outside the bounds; unknown")
}

fn return_record_opt_standard_impl<'a,F>(closure:Box<F>) -> Option<&'a BlockchainRecord>
    where
        F: FnMut(&&BlockchainRecord) -> bool,{
    return_record_opt_body(closure,&CHAINS)
}

fn return_record_opt_body<F>(closure: Box<F>, collection_of_chains:&[BlockchainRecord]) -> Option<&BlockchainRecord>
    where
        F: FnMut(&&BlockchainRecord) -> bool,
{
    let mut filtered = collection_of_chains.iter().filter(closure).collect_vec();
    filtered.pop().map(|first|if filtered.pop() != None {panic!("Not unique identifier used to query a BlockchainRecord")} else {first})
}

fn return_record_by_chain_id(chain_id: u8) -> &'static BlockchainRecord {
    return_record(Box::new(|b: &&BlockchainRecord| b.num_chain_id == chain_id))
}

fn return_record_by_chain_name(chain_name: &str) -> &'static BlockchainRecord {
    return_record(Box::new(|b: &&BlockchainRecord| {
        b.in_command_name == chain_name
    }))
}

fn return_record_by_blockchain_name(
    blockchain_name: Blockchain,
) -> &'static BlockchainRecord {
    return_record(Box::new(|b: &&BlockchainRecord| {
        b.literal_chain_id == blockchain_name
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::neighborhood::Blockchain;
    use web3::types::Address;

    #[test]
    #[should_panic(expected = "chain outside the bounds; unknown")]
    fn return_record_reliably_panics_if_nonexistent_chain_requested_as_lower() {
        let first_lower_nonexistent = 0;

        let _ = return_record(Box::new(|b: &&BlockchainRecord| {
            b.num_chain_id == first_lower_nonexistent
        }));
    }

    #[test]
    #[should_panic(expected = "chain outside the bounds; unknown")]
    fn return_record_reliably_panics_if_nonexistent_chain_requested_as_higher() {
        let mut cashed_biggest_id = 0_u8;
        CHAINS.iter().for_each(|b_record|if b_record.num_chain_id > cashed_biggest_id { cashed_biggest_id = b_record.num_chain_id});

        let _ = return_record(Box::new(|b: &&BlockchainRecord| {
            b.num_chain_id == cashed_biggest_id + 1
        }));
    }

    #[test]
    #[should_panic(expected = "Not unique identifier used to query a BlockchainRecord")]
    fn return_record_opt_panics_if_more_records_meet_the_condition_from_the_closure(){
        let searched_name = "BruhBruh";
        let mut record_one = make_defaulted_blockchain_record();
        record_one.in_command_name = searched_name;
        let mut record_two = make_defaulted_blockchain_record();
        record_two.in_command_name = "Jooodooo";
        let mut record_three = make_defaulted_blockchain_record();
        record_three.in_command_name = searched_name;
        let collection = [record_one,record_two,record_three];

        let _ = return_record_opt_body(Box::new(|b:&&BlockchainRecord|{b.in_command_name == searched_name}), &collection);
    }

    #[test]
    fn return_record_opt_standard_impl_uses_the_true_collection_of_chains(){
        CHAINS.iter().for_each(|record| assert_eq!(record,return_record_opt_standard_impl(Box::new(|b:&&BlockchainRecord|b.num_chain_id == record.num_chain_id )).unwrap()));
    }

    #[test]
    fn return_record_uses_the_true_collection_of_chains(){
        CHAINS.iter().for_each(|record| assert_eq!(record,return_record(Box::new(|b:&&BlockchainRecord|b.num_chain_id == record.num_chain_id ))));
    }

    #[test]
    fn eth_mainnet_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::EthMainnet);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 1,
                literal_chain_id: Blockchain::EthMainnet,
                in_command_name: "eth-mainnet",
                directory_by_platform: "eth",
                chain_label: "eth",
                contract: MAINNET_CONTRACT_ADDRESS,
                contract_creation_block: MAINNET_CONTRACT_CREATION_BLOCK,
            }
        )
    }

    #[test]
    fn ropsten_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::EthRopsten);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 3,
                literal_chain_id: Blockchain::EthRopsten,
                in_command_name: "ropsten",
                directory_by_platform: "eth",
                chain_label: "eth_t1",
                contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
            }
        )
    }

    #[test]
    fn rinkeby_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::EthRinkeby);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 4,
                literal_chain_id: Blockchain::EthRinkeby,
                in_command_name: "rinkeby",
                directory_by_platform: "eth",
                chain_label: "eth_t2",
                contract: RINKEBY_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK
            }
        )
    }

    #[test]
    fn multinode_testnet_chain_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::Dev);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 5,
                literal_chain_id: Blockchain::Dev,
                in_command_name: "dev",
                directory_by_platform: "dev",
                chain_label: "dev",
                contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: 0
            }
        )
    }

    fn return_examined<'a>(blockchain: Blockchain) -> &'a BlockchainRecord {
        CHAINS
            .iter()
            .find(|chain| chain.literal_chain_id == blockchain)
            .unwrap()
    }

    #[test]
    fn contract_from_chain_id_works() {
        assert_contract_from_chain_id(Blockchain::EthMainnet, MAINNET_CONTRACT_ADDRESS);
        assert_contract_from_chain_id(Blockchain::EthRopsten, ROPSTEN_TESTNET_CONTRACT_ADDRESS);
        assert_contract_from_chain_id(Blockchain::EthRinkeby, RINKEBY_TESTNET_CONTRACT_ADDRESS);
        assert_contract_from_chain_id(Blockchain::Dev, MULTINODE_TESTNET_CONTRACT_ADDRESS);
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_contract_from_chain_id(blockchain: Blockchain, expected_contract: Address) {
        assert_eq!(
            contract_address(chain_id_from_blockchain(blockchain)),
            expected_contract
        )
    }

    #[test]
    fn contract_creation_block_works() {
        assert_creation_block_from_chain_id(
            Blockchain::EthMainnet,
            MAINNET_CONTRACT_CREATION_BLOCK,
        );
        assert_creation_block_from_chain_id(
            Blockchain::EthRopsten,
            ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
        );
        assert_creation_block_from_chain_id(
            Blockchain::EthRinkeby,
            RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK,
        );
        assert_creation_block_from_chain_id(
            Blockchain::Dev,
            MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
        );
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_creation_block_from_chain_id(blockchain: Blockchain, expected_block_number: u64) {
        assert_eq!(
            contract_creation_block_from_chain_id(chain_id_from_blockchain(blockchain)),
            expected_block_number
        )
    }

    #[test]
    fn chain_name_from_id_works() {
        assert_chain_name_from_chain_id(Blockchain::EthMainnet, "eth-mainnet");
        assert_chain_name_from_chain_id(Blockchain::EthRopsten, "ropsten");
        assert_chain_name_from_chain_id(Blockchain::EthRinkeby, "rinkeby");
        assert_chain_name_from_chain_id(Blockchain::Dev, "dev");
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_chain_name_from_chain_id(blockchain: Blockchain, expected_name: &str) {
        assert_eq!(
            chain_name_from_id(chain_id_from_blockchain(blockchain)),
            expected_name
        )
    }

    #[test]
    fn blockchain_from_id_works() {
        assert_blockchain_from_chain_id(Blockchain::EthMainnet, Blockchain::EthMainnet);
        assert_blockchain_from_chain_id(Blockchain::EthRopsten, Blockchain::EthRopsten);
        assert_blockchain_from_chain_id(Blockchain::EthRinkeby, Blockchain::EthRinkeby);
        assert_blockchain_from_chain_id(Blockchain::Dev, Blockchain::Dev);
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_blockchain_from_chain_id(blockchain: Blockchain, expected_blockchain: Blockchain) {
        assert_eq!(
            blockchain_from_chain_id(chain_id_from_blockchain(blockchain)),
            expected_blockchain
        )
    }

    #[test]
    fn chain_name_from_blockchain_works() {
        assert_chain_name_from_blockchain(Blockchain::EthMainnet, "eth-mainnet");
        assert_chain_name_from_blockchain(Blockchain::EthRopsten, "ropsten");
        assert_chain_name_from_blockchain(Blockchain::EthRinkeby, "rinkeby");
        assert_chain_name_from_blockchain(Blockchain::Dev, "dev");
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_chain_name_from_blockchain(blockchain: Blockchain, expected_name: &str) {
        assert_eq!(chain_name_from_blockchain(blockchain), expected_name)
    }

    #[test]
    fn chain_id_from_name_works() {
        assert_chain_id_from_name(Blockchain::EthMainnet, 1);
        assert_chain_id_from_name(Blockchain::EthRopsten, 3);
        assert_chain_id_from_name(Blockchain::EthRinkeby, 4);
        assert_chain_id_from_name(Blockchain::Dev, 5);
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_chain_id_from_name(blockchain: Blockchain, expected_id: u8) {
        assert_eq!(
            chain_id_from_name(chain_name_from_blockchain(blockchain)),
            expected_id
        )
    }

    #[test]
    fn chain_id_from_blockchain_works() {
        assert_chain_id_from_blockchain(Blockchain::EthMainnet, 1);
        assert_chain_id_from_blockchain(Blockchain::EthRopsten, 3);
        assert_chain_id_from_blockchain(Blockchain::EthRinkeby, 4);
        assert_chain_id_from_blockchain(Blockchain::Dev, 5);
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_chain_id_from_blockchain(blockchain: Blockchain, expected_id: u8) {
        assert_eq!(chain_id_from_blockchain(blockchain), expected_id)
    }

    #[test]
    fn platform_from_name_works() {
        assert_platform_from_name(Blockchain::EthMainnet, "eth");
        assert_platform_from_name(Blockchain::EthRopsten, "eth");
        assert_platform_from_name(Blockchain::EthRinkeby, "eth");
        assert_platform_from_name(Blockchain::Dev, "dev");
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_platform_from_name(blockchain: Blockchain, expected_platform: &str) {
        assert_eq!(
            platform_from_chain_name(chain_name_from_blockchain(blockchain)),
            expected_platform
        )
    }

    #[test]
    fn label_from_blockchain_works() {
        assert_label_from_blockchain(Blockchain::EthMainnet, "eth");
        assert_label_from_blockchain(Blockchain::EthRopsten, "eth_t1");
        assert_label_from_blockchain(Blockchain::EthRinkeby, "eth_t2");
        assert_label_from_blockchain(Blockchain::Dev, "dev");
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_label_from_blockchain(blockchain: Blockchain, expected_label: &str) {
        assert_eq!(label_from_blockchain(blockchain), expected_label)
    }

    #[test]
    fn blockchain_from_label_opt_works() {
        assert_blockchain_from_label_opt("eth", Some(Blockchain::EthMainnet));
        assert_blockchain_from_label_opt("eth_t1", Some(Blockchain::EthRopsten));
        assert_blockchain_from_label_opt("eth_t2", Some(Blockchain::EthRinkeby));
        assert_blockchain_from_label_opt("dev", Some(Blockchain::Dev));
        assert_blockchain_from_label_opt("bitcoin", None);
        assert_eq!(CHAINS.len(), 4)
    }

    fn assert_blockchain_from_label_opt(label: &str, expected_blockchain: Option<Blockchain>) {
        assert_eq!(blockchain_from_label_opt(label), expected_blockchain)
    }

    fn make_defaulted_blockchain_record()->BlockchainRecord{
        BlockchainRecord{
            num_chain_id: 0,
            literal_chain_id: Blockchain::EthMainnet,
            in_command_name: "",
            directory_by_platform: "",
            chain_label: "",
            contract: Default::default(),
            contract_creation_block: 0
        }
    }
}
