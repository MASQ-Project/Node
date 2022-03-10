// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use const_format::concatcp;

pub const DEFAULT_CHAIN: Chain = Chain::PolyMainnet;

pub const HIGHEST_RANDOM_CLANDESTINE_PORT: u16 = 9999;
pub const HTTP_PORT: u16 = 80;
pub const TLS_PORT: u16 = 443;
pub const MASQ_URL_PREFIX: &str = "masq://";
pub const DEFAULT_GAS_PRICE: u64 = 1;
pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;
pub const DEFAULT_UI_PORT: u16 = 5333;
pub const CURRENT_LOGFILE_NAME: &str = "MASQNode_rCURRENT.log";
pub const MASQ_PROMPT: &str = "masq> ";

pub const ETH_MAINNET_CONTRACT_CREATION_BLOCK: u64 = 11_170_708;
pub const ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK: u64 = 8_688_171;
pub const MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK: u64 = 0;
pub const POLYGON_MAINNET_CONTRACT_CREATION_BLOCK: u64 = 14_863_650;
pub const MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK: u64 = 24_638_838;

//error codes
////////////////////////////////////////////////////////////////////////////////////////////////////

//moved from configurator
pub const CONFIGURATOR_PREFIX: u64 = 0x0001_0000_0000_0000;
pub const CONFIGURATOR_READ_ERROR: u64 = CONFIGURATOR_PREFIX | 1;
pub const CONFIGURATOR_WRITE_ERROR: u64 = CONFIGURATOR_PREFIX | 2;
pub const UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR: u64 = CONFIGURATOR_PREFIX | 3;
pub const ILLEGAL_MNEMONIC_WORD_COUNT_ERROR: u64 = CONFIGURATOR_PREFIX | 4;
pub const KEY_PAIR_CONSTRUCTION_ERROR: u64 = CONFIGURATOR_PREFIX | 5;
pub const BAD_PASSWORD_ERROR: u64 = CONFIGURATOR_PREFIX | 6;
pub const ALREADY_INITIALIZED_ERROR: u64 = CONFIGURATOR_PREFIX | 7;
pub const DERIVATION_PATH_ERROR: u64 = CONFIGURATOR_PREFIX | 8;
pub const MNEMONIC_PHRASE_ERROR: u64 = CONFIGURATOR_PREFIX | 9;
pub const EARLY_QUESTIONING_ABOUT_DATA: u64 = CONFIGURATOR_PREFIX | 10;
pub const UNRECOGNIZED_PARAMETER: u64 = CONFIGURATOR_PREFIX | 11;
pub const NON_PARSABLE_VALUE: u64 = CONFIGURATOR_PREFIX | 12;
pub const MISSING_DATA: u64 = CONFIGURATOR_PREFIX | 13;
pub const UNKNOWN_ERROR: u64 = CONFIGURATOR_PREFIX | 14;

//moved from masq_lib/messages
pub const UI_NODE_COMMUNICATION_PREFIX: u64 = 0x8000_0000_0000_0000;
pub const NODE_LAUNCH_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 1;
pub const NODE_NOT_RUNNING_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 2;
pub const NODE_ALREADY_RUNNING_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 3;
pub const UNMARSHAL_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 4;
pub const SETUP_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 5;
pub const TIMEOUT_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 6;

////////////////////////////////////////////////////////////////////////////////////////////////////

pub const COMBINED_PARAMETERS_DELIMITER: char = '|';

//descriptor
pub const CENTRAL_DELIMITER: char = '@';
pub const CHAIN_IDENTIFIER_DELIMITER: char = ':';

//chains
const MAINNET: &str = "mainnet";
const POLYGON_FAMILY: &str = "polygon";
const ETH_FAMILY: &str = "eth";
const LINK: char = '-';
pub const POLYGON_MAINNET_FULL_IDENTIFIER: &str = concatcp!(POLYGON_FAMILY, LINK, MAINNET);
pub const POLYGON_MUMBAI_FULL_IDENTIFIER: &str = concatcp!(POLYGON_FAMILY, LINK, "mumbai");
pub const DEV_CHAIN_FULL_IDENTIFIER: &str = "dev";
pub const ETH_MAINNET_FULL_IDENTIFIER: &str = concatcp!(ETH_FAMILY, LINK, MAINNET);
pub const ETH_ROPSTEN_FULL_IDENTIFIER: &str = concatcp!(ETH_FAMILY, LINK, "ropsten");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(DEFAULT_CHAIN, Chain::PolyMainnet);
        assert_eq!(HIGHEST_RANDOM_CLANDESTINE_PORT, 9999);
        assert_eq!(HTTP_PORT, 80);
        assert_eq!(TLS_PORT, 443);
        assert_eq!(MASQ_URL_PREFIX, "masq://");
        assert_eq!(DEFAULT_GAS_PRICE, 1);
        assert_eq!(LOWEST_USABLE_INSECURE_PORT, 1025);
        assert_eq!(HIGHEST_USABLE_PORT, 65535);
        assert_eq!(DEFAULT_UI_PORT, 5333);
        assert_eq!(CURRENT_LOGFILE_NAME, "MASQNode_rCURRENT.log");
        assert_eq!(MASQ_PROMPT, "masq> ");
        assert_eq!(ETH_MAINNET_CONTRACT_CREATION_BLOCK, 11_170_708);
        assert_eq!(ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK, 8_688_171);
        assert_eq!(MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK, 0);
        assert_eq!(POLYGON_MAINNET_CONTRACT_CREATION_BLOCK, 14_863_650);
        assert_eq!(MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK, 24_638_838);
        assert_eq!(CONFIGURATOR_PREFIX, 0x0001_0000_0000_0000);
        assert_eq!(CONFIGURATOR_READ_ERROR, CONFIGURATOR_PREFIX | 1);
        assert_eq!(CONFIGURATOR_WRITE_ERROR, CONFIGURATOR_PREFIX | 2);
        assert_eq!(
            UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR,
            CONFIGURATOR_PREFIX | 3
        );
        assert_eq!(ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, CONFIGURATOR_PREFIX | 4);
        assert_eq!(KEY_PAIR_CONSTRUCTION_ERROR, CONFIGURATOR_PREFIX | 5);
        assert_eq!(BAD_PASSWORD_ERROR, CONFIGURATOR_PREFIX | 6);
        assert_eq!(ALREADY_INITIALIZED_ERROR, CONFIGURATOR_PREFIX | 7);
        assert_eq!(DERIVATION_PATH_ERROR, CONFIGURATOR_PREFIX | 8);
        assert_eq!(MNEMONIC_PHRASE_ERROR, CONFIGURATOR_PREFIX | 9);
        assert_eq!(EARLY_QUESTIONING_ABOUT_DATA, CONFIGURATOR_PREFIX | 10);
        assert_eq!(UNRECOGNIZED_PARAMETER, CONFIGURATOR_PREFIX | 11);
        assert_eq!(NON_PARSABLE_VALUE, CONFIGURATOR_PREFIX | 12);
        assert_eq!(MISSING_DATA, CONFIGURATOR_PREFIX | 13);
        assert_eq!(UNKNOWN_ERROR, CONFIGURATOR_PREFIX | 14);
        assert_eq!(UI_NODE_COMMUNICATION_PREFIX, 0x8000_0000_0000_0000);
        assert_eq!(NODE_LAUNCH_ERROR, UI_NODE_COMMUNICATION_PREFIX | 1);
        assert_eq!(NODE_NOT_RUNNING_ERROR, UI_NODE_COMMUNICATION_PREFIX | 2);
        assert_eq!(NODE_ALREADY_RUNNING_ERROR, UI_NODE_COMMUNICATION_PREFIX | 3);
        assert_eq!(UNMARSHAL_ERROR, UI_NODE_COMMUNICATION_PREFIX | 4);
        assert_eq!(SETUP_ERROR, UI_NODE_COMMUNICATION_PREFIX | 5);
        assert_eq!(TIMEOUT_ERROR, UI_NODE_COMMUNICATION_PREFIX | 6);
        assert_eq!(CENTRAL_DELIMITER, '@');
        assert_eq!(CHAIN_IDENTIFIER_DELIMITER, ':');
        assert_eq!(MAINNET, "mainnet");
        assert_eq!(POLYGON_FAMILY, "polygon");
        assert_eq!(ETH_FAMILY, "eth");
        assert_eq!(LINK, '-');
        assert_eq!(POLYGON_MAINNET_FULL_IDENTIFIER, "polygon-mainnet");
        assert_eq!(POLYGON_MUMBAI_FULL_IDENTIFIER, "polygon-mumbai");
        assert_eq!(DEV_CHAIN_FULL_IDENTIFIER, "dev");
        assert_eq!(ETH_MAINNET_FULL_IDENTIFIER, "eth-mainnet");
        assert_eq!(ETH_ROPSTEN_FULL_IDENTIFIER, "eth-ropsten");
    }
}
