// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::wallet::Wallet;
use masq_lib::blockchains::chains::Chain;
use web3::types::U256;

const TRANSFER_METHOD_ID: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

pub fn transaction_data_web3(recipient: &Wallet, amount: u128) -> [u8; 68] {
    let mut data = [0u8; 4 + 32 + 32];
    data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
    data[16..36].copy_from_slice(&recipient.address().0[..]);
    U256::try_from(amount)
        .expect("shouldn't overflow")
        .to_big_endian(&mut data[36..68]);
    data
}

pub fn compute_gas_limit(gas_limit_const_part: u64, data: &[u8]) -> U256 {
    ethereum_types::U256::try_from(data.iter().fold(gas_limit_const_part, |acc, v| {
        acc + if v == &0u8 { 4 } else { 68 }
    }))
    .expect("Internal error")
}

pub fn web3_gas_limit_const_part(chain: Chain) -> u64 {
    match chain {
        Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
        Chain::PolyMainnet | Chain::PolyMumbai => 70_000,
    }
}

#[cfg(test)]
mod tests {
    use crate::sub_lib::blockchain_interface_web3::{
        web3_gas_limit_const_part, TRANSFER_METHOD_ID,
    };
    use ethsign_crypto::Keccak256;
    use masq_lib::blockchains::chains::Chain;

    #[test]
    fn constants_are_correct() {
        assert_eq!(TRANSFER_METHOD_ID, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn hash_the_smart_contract_transfer_function_signature() {
        assert_eq!(
            "transfer(address,uint256)".keccak256()[0..4],
            TRANSFER_METHOD_ID,
        );
    }

    #[test]
    fn web3_gas_limit_const_part_returns_reasonable_values() {
        assert_eq!(web3_gas_limit_const_part(Chain::EthMainnet), 55_000);
        assert_eq!(web3_gas_limit_const_part(Chain::EthRopsten), 55_000);
        assert_eq!(web3_gas_limit_const_part(Chain::PolyMainnet), 70_000);
        assert_eq!(web3_gas_limit_const_part(Chain::PolyMumbai), 70_000);
        assert_eq!(web3_gas_limit_const_part(Chain::Dev), 55_000);
    }
}
