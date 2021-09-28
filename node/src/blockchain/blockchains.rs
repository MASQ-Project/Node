// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::{
    MAINNET_CONTRACT_ADDRESS, MULTINODE_TESTNET_CONTRACT_ADDRESS, RINKEBY_TESTNET_CONTRACT_ADDRESS,
    ROPSTEN_TESTNET_CONTRACT_ADDRESS,
};
use crate::blockchain::blockchains_specific_constants::{
    MAINNET_CONTRACT_CREATION_BLOCK, MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
    RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK, ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
};
use crate::sub_lib::neighborhood::Blockchain;
use web3::types::Address;

pub const KEY_VS_IP_DELIMITER: char = ':';
pub const CHAIN_LABEL_DELIMITER: char = '.';

pub const CHAINS: [BlockchainRecord; 4] = [
    BlockchainRecord {
        num_chain_id: 1,
        non_num_chain_id: Blockchain::EthMainnet,
        in_command_name: "eth-mainnet",
        directory_by_platform: "eth",
        delimiter: '@',
        contract: MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 2,
        non_num_chain_id: Blockchain::EthRopsten,
        in_command_name: "ropsten",
        directory_by_platform: "eth",
        delimiter: ':',
        contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 3,
        non_num_chain_id: Blockchain::EthRinkeby,
        in_command_name: "rinkeby",
        directory_by_platform: "eth",
        delimiter: ':',
        contract: RINKEBY_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 4,
        non_num_chain_id: Blockchain::Dev,
        in_command_name: "dev",
        directory_by_platform: "dev",
        delimiter: ':',
        contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
    },
];

#[derive(Debug, PartialEq)]
pub struct BlockchainRecord {
    pub num_chain_id: u8,
    pub non_num_chain_id: Blockchain,
    pub in_command_name: ChainName,
    pub directory_by_platform: &'static str,
    pub delimiter: char,
    pub contract: Address,
    pub contract_creation_block: u64,
}

type ChainName = &'static str;

#[track_caller]
fn return_right_record<F>(closure: Box<F>) -> &'static BlockchainRecord
where
    F: FnMut(&&BlockchainRecord) -> bool,
{
    CHAINS
        .iter()
        .find(closure)
        .expect("chain outside the bounds; unknown")
}

fn return_right_record_by_chain_id(chain_id: u8) -> &'static BlockchainRecord {
    return_right_record(Box::new(|b: &&BlockchainRecord| b.num_chain_id == chain_id))
}

fn return_right_record_by_chain_name(chain_name: &str) -> &'static BlockchainRecord {
    return_right_record(Box::new(|b: &&BlockchainRecord| {
        b.in_command_name == chain_name
    }))
}

fn return_right_record_by_blockchain_name(
    blockchain_name: Blockchain,
) -> &'static BlockchainRecord {
    return_right_record(Box::new(|b: &&BlockchainRecord| {
        b.non_num_chain_id == blockchain_name
    }))
}

pub fn contract_address(chain_id: u8) -> Address {
    return_right_record_by_chain_id(chain_id).contract
}

pub fn contract_creation_block_from_chain_id(chain_id: u8) -> u64 {
    return_right_record_by_chain_id(chain_id).contract_creation_block
}

pub fn chain_name_from_id(chain_id: u8) -> &'static str {
    return_right_record_by_chain_id(chain_id).in_command_name
}

pub fn chain_name_from_blockchain(blockchain_name: Blockchain) -> &'static str {
    chain_name_from_id(chain_id_from_blockchain(blockchain_name))
}

pub fn chain_id_from_blockchain(blockchain: Blockchain) -> u8 {
    return_right_record_by_blockchain_name(blockchain).num_chain_id
}

pub fn chain_id_from_name(chain_name: &str) -> u8 {
    return_right_record_by_chain_name(chain_name).num_chain_id
}

pub fn blockchain_from_chain_id(chain_id: u8) -> Blockchain {
    return_right_record_by_chain_id(chain_id).non_num_chain_id
}

pub fn platform_from_chain_name(chain_name: &str) -> &str {
    return_right_record_by_chain_name(chain_name).directory_by_platform
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::{
        MAINNET_CONTRACT_ADDRESS, MULTINODE_TESTNET_CONTRACT_ADDRESS,
        RINKEBY_TESTNET_CONTRACT_ADDRESS, ROPSTEN_TESTNET_CONTRACT_ADDRESS,
    };
    use crate::blockchain::blockchains::{
        blockchain_from_chain_id, chain_id_from_blockchain, chain_id_from_name,
        chain_name_from_blockchain, chain_name_from_id, contract_address,
        contract_creation_block_from_chain_id, platform_from_chain_name, return_right_record,
        BlockchainRecord, CHAINS,
    };
    use crate::blockchain::blockchains_specific_constants::{
        MAINNET_CONTRACT_CREATION_BLOCK, MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK,
        RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK, ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
    };
    use crate::sub_lib::neighborhood::Blockchain;
    use web3::types::Address;

    #[test]
    #[should_panic(expected = "chain outside the bounds; unknown")]
    fn return_right_record_reliably_panics_if_nonexistent_chain_requested() {
        let _ = return_right_record(Box::new(|b: &&BlockchainRecord| b.num_chain_id == u8::MAX));
    }

    #[test]
    fn eth_mainnet_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::EthMainnet);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 1,
                non_num_chain_id: Blockchain::EthMainnet,
                in_command_name: "eth-mainnet",
                directory_by_platform: "eth",
                delimiter: '@',
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
                num_chain_id: 2,
                non_num_chain_id: Blockchain::EthRopsten,
                in_command_name: "ropsten",
                directory_by_platform: "eth",
                delimiter: ':',
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
                num_chain_id: 3,
                non_num_chain_id: Blockchain::EthRinkeby,
                in_command_name: "rinkeby",
                directory_by_platform: "eth",
                delimiter: ':',
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
                num_chain_id: 4,
                non_num_chain_id: Blockchain::Dev,
                in_command_name: "dev",
                directory_by_platform: "dev",
                delimiter: ':',
                contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: 0
            }
        )
    }

    fn return_examined<'a>(blockchain: Blockchain) -> &'a BlockchainRecord {
        CHAINS
            .iter()
            .find(|chain| chain.non_num_chain_id == blockchain)
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
        assert_chain_id_from_name(Blockchain::EthRopsten, 2);
        assert_chain_id_from_name(Blockchain::EthRinkeby, 3);
        assert_chain_id_from_name(Blockchain::Dev, 4);
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
        assert_chain_id_from_blockchain(Blockchain::EthRopsten, 2);
        assert_chain_id_from_blockchain(Blockchain::EthRinkeby, 3);
        assert_chain_id_from_blockchain(Blockchain::Dev, 4);
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
}
