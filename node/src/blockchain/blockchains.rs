// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::{MAINNET_CONTRACT_ADDRESS, MAINNET_CONTRACT_CREATION_BLOCK, MULTINODE_TESTNET_CONTRACT_ADDRESS, ROPSTEN_TESTNET_CONTRACT_ADDRESS, ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK, RINKEBY_TESTNET_CONTRACT_ADDRESS, RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK};
use crate::sub_lib::neighborhood::Blockchain;
use web3::types::Address;

const CHAINS: [BlockchainRecord; 4] = [
    BlockchainRecord {
        num_chain_id: 1,
        non_num_id: Blockchain::EthMainnet,
        in_command_name: "eth-mainnet",
        delimiter: '@',
        contract: MAINNET_CONTRACT_ADDRESS,
        contract_creation_block: MAINNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 2,
        non_num_id: Blockchain::EthRopsten,
        in_command_name: "ropsten",
        delimiter: ':',
        contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 3,
        non_num_id: Blockchain::EthRinkeby,
        in_command_name: "rinkeby",
        delimiter: ':',
        contract: RINKEBY_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK,
    },
    BlockchainRecord {
        num_chain_id: 4,
        non_num_id: Blockchain::Dev,
        in_command_name: "dev",
        delimiter: ':',
        contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
        contract_creation_block: 0,
    },
];

#[derive(Debug, PartialEq)]
pub struct BlockchainRecord {
    pub num_chain_id: u8,
    pub non_num_id: Blockchain,
    pub in_command_name: ChainName,
    pub delimiter: char,
    pub contract: Address,
    pub contract_creation_block: u64,
}

type ChainName = &'static str;

fn return_right_record<F>(closure: Box<F>)->&'static BlockchainRecord
where F: FnMut(&&BlockchainRecord)->bool{
    CHAINS.iter().find(closure).expect("chain outside the bounds")
}

pub fn contract_from_chain_id(chain_id: u8) -> Address {
    return_right_record(Box::new(|b:&&BlockchainRecord|b.num_chain_id == chain_id)).contract
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::{MAINNET_CONTRACT_ADDRESS, MAINNET_CONTRACT_CREATION_BLOCK, RINKEBY_TESTNET_CONTRACT_ADDRESS, RINKEBY_TESTNET_CONTRACT_CREATION_BLOCK, ROPSTEN_TESTNET_CONTRACT_ADDRESS, ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK, MULTINODE_TESTNET_CONTRACT_ADDRESS};
    use crate::blockchain::blockchains::{BlockchainRecord, CHAINS, contract_from_chain_id, return_right_record};
    use crate::sub_lib::neighborhood::Blockchain;

    #[test]
    fn eth_mainnet_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::EthMainnet);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 1,
                non_num_id: Blockchain::EthMainnet,
                in_command_name: "eth-mainnet",
                delimiter: '@',
                contract: MAINNET_CONTRACT_ADDRESS,
                contract_creation_block: MAINNET_CONTRACT_CREATION_BLOCK,
            }
        )
    }

    #[test]
    fn Ropsten_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::EthRopsten);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 2,
                non_num_id: Blockchain::EthRopsten,
                in_command_name: "ropsten",
                delimiter: ':',
                contract: ROPSTEN_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK,
            }
        )
    }

    #[test]
    fn Rinkeby_record_is_properly_defined() {
        let examined_chain = return_examined(Blockchain::EthRinkeby);
        assert_eq!(
            examined_chain,
            &BlockchainRecord {
                num_chain_id: 3,
                non_num_id: Blockchain::EthRinkeby,
                in_command_name: "rinkeby",
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
                non_num_id: Blockchain::Dev,
                in_command_name: "dev",
                delimiter: ':',
                contract: MULTINODE_TESTNET_CONTRACT_ADDRESS,
                contract_creation_block: 0
            }
        )
    }

    fn return_examined<'a>(blockchain: Blockchain) -> &'a BlockchainRecord {
        CHAINS
            .iter()
            .find(|chain| chain.non_num_id == blockchain)
            .unwrap()
    }

    #[test]
    fn contract_from_chain_id_works() {
        let chain_id = 3;

        let result = contract_from_chain_id(chain_id);

        assert_eq!(result,RINKEBY_TESTNET_CONTRACT_ADDRESS)
    }

}
