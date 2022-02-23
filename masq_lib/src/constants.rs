// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use const_format::concatcp;

pub const DEFAULT_CHAIN: Chain = Chain::EthMainnet; // tested

pub const HIGHEST_RANDOM_CLANDESTINE_PORT: u16 = 9999; // tested
pub const HTTP_PORT: u16 = 80; // tested
pub const TLS_PORT: u16 = 443; // tested
pub const MASQ_URL_PREFIX: &str = "masq://"; // tested
pub const DEFAULT_GAS_PRICE: u64 = 1; // tested
pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025; // tested
pub const HIGHEST_USABLE_PORT: u16 = 65535; // tested
pub const DEFAULT_UI_PORT: u16 = 5333; // tested
pub const CURRENT_LOGFILE_NAME: &str = "MASQNode_rCURRENT.log"; // tested

pub const MASQ_PROMPT: &str = "masq> "; // tested

pub const ETH_MAINNET_CONTRACT_CREATION_BLOCK: u64 = 11_170_708; // tested
pub const ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK: u64 = 8_688_171; // tested
pub const MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK: u64 = 0; // tested
pub const POLYGON_MAINNET_CONTRACT_CREATION_BLOCK: u64 = 14_863_650; // tested
pub const MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK: u64 = 24_638_838; // tested

//error codes

//moved from configurator
pub const CONFIGURATOR_PREFIX: u64 = 0x0001_0000_0000_0000; // tested
pub const CONFIGURATOR_READ_ERROR: u64 = CONFIGURATOR_PREFIX | 1; // tested
pub const CONFIGURATOR_WRITE_ERROR: u64 = CONFIGURATOR_PREFIX | 2; // tested
pub const UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR: u64 = CONFIGURATOR_PREFIX | 3; // tested
pub const ILLEGAL_MNEMONIC_WORD_COUNT_ERROR: u64 = CONFIGURATOR_PREFIX | 4; // tested
pub const KEY_PAIR_CONSTRUCTION_ERROR: u64 = CONFIGURATOR_PREFIX | 5; // tested
pub const BAD_PASSWORD_ERROR: u64 = CONFIGURATOR_PREFIX | 6; // tested
pub const ALREADY_INITIALIZED_ERROR: u64 = CONFIGURATOR_PREFIX | 7; // tested
pub const DERIVATION_PATH_ERROR: u64 = CONFIGURATOR_PREFIX | 8; // tested
pub const MNEMONIC_PHRASE_ERROR: u64 = CONFIGURATOR_PREFIX | 9; // tested
pub const EARLY_QUESTIONING_ABOUT_DATA: u64 = CONFIGURATOR_PREFIX | 10; // tested
pub const UNRECOGNIZED_PARAMETER: u64 = CONFIGURATOR_PREFIX | 11; // tested
pub const NON_PARSABLE_VALUE: u64 = CONFIGURATOR_PREFIX | 12; // tested
pub const MISSING_DATA: u64 = CONFIGURATOR_PREFIX | 13; // tested
pub const UNKNOWN_ERROR: u64 = CONFIGURATOR_PREFIX | 14; // tested

//moved from masq_lib/messages
pub const UI_NODE_COMMUNICATION_PREFIX: u64 = 0x8000_0000_0000_0000; // tested
pub const NODE_LAUNCH_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 1; // tested
pub const NODE_NOT_RUNNING_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 2; // tested
pub const NODE_ALREADY_RUNNING_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 3; // tested
pub const UNMARSHAL_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 4; // tested
pub const SETUP_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 5; // tested
pub const TIMEOUT_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 6; // tested

//descriptor
pub const CENTRAL_DELIMITER: char = '@'; // tested
pub const CHAIN_IDENTIFIER_DELIMITER: char = ':'; // tested

//chains
const MAINNET: &str = "mainnet"; // tested
const POLYGON_FAMILY: &str = "polygon"; // tested
const ETH_FAMILY: &str = "eth"; // tested
const LINK: char = '-'; // tested
pub const POLYGON_MAINNET_FULL_IDENTIFIER: &str = concatcp!(POLYGON_FAMILY, LINK, MAINNET); // tested
pub const POLYGON_MUMBAI_FULL_IDENTIFIER: &str = concatcp!(POLYGON_FAMILY, LINK, "mumbai"); // tested
pub const DEV_CHAIN_FULL_IDENTIFIER: &str = "dev"; // tested
pub const ETH_MAINNET_FULL_IDENTIFIER: &str = concatcp!(ETH_FAMILY, LINK, MAINNET); // tested
pub const ETH_ROPSTEN_FULL_IDENTIFIER: &str = concatcp!(ETH_FAMILY, LINK, "ropsten"); // tested

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn DEFAULT_CHAIN_constant_has_correct_value() {
        assert_eq!(DEFAULT_CHAIN, Chain::EthMainnet);
    }

    #[test]
    fn HIGHEST_RANDOM_CLANDESTINE_PORT_constant_has_correct_value() {
        assert_eq!(HIGHEST_RANDOM_CLANDESTINE_PORT, 9999);
    }

    #[test]
    fn HTTP_PORT_constant_has_correct_value() {
        assert_eq!(HTTP_PORT, 80);
    }

    #[test]
    fn TLS_PORT_constant_has_correct_value() {
        assert_eq!(TLS_PORT, 443);
    }

    #[test]
    fn MASQ_URL_PREFIX_constant_has_correct_value() {
        assert_eq!(MASQ_URL_PREFIX, "masq://");
    }

    #[test]
    fn DEFAULT_GAS_PRICE_constant_has_correct_value() {
        assert_eq!(DEFAULT_GAS_PRICE, 1);
    }

    #[test]
    fn LOWEST_USABLE_INSECURE_PORT_constant_has_correct_value() {
        assert_eq!(LOWEST_USABLE_INSECURE_PORT, 1025);
    }

    #[test]
    fn HIGHEST_USABLE_PORT_constant_has_correct_value() {
        assert_eq!(HIGHEST_USABLE_PORT, 65535);
    }

    #[test]
    fn DEFAULT_UI_PORT_constant_has_correct_value() {
        assert_eq!(DEFAULT_UI_PORT, 5333);
    }

    #[test]
    fn CURRENT_LOGFILE_NAME_constant_has_correct_value() {
        assert_eq!(CURRENT_LOGFILE_NAME, "MASQNode_rCURRENT.log");
    }

    #[test]
    fn MASQ_PROMPT_constant_has_correct_value() {
        assert_eq!(MASQ_PROMPT, "masq> ");
    }

    #[test]
    fn ETH_MAINNET_CONTRACT_CREATION_BLOCK_constant_has_correct_value() {
        assert_eq!(ETH_MAINNET_CONTRACT_CREATION_BLOCK, 11_170_708);
    }

    #[test]
    fn ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK_constant_has_correct_value() {
        assert_eq!(ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK, 8_688_171);
    }

    #[test]
    fn MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK_constant_has_correct_value() {
        assert_eq!(MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK, 0);
    }

    #[test]
    fn POLYGON_MAINNET_CONTRACT_CREATION_BLOCK_constant_has_correct_value() {
        assert_eq!(POLYGON_MAINNET_CONTRACT_CREATION_BLOCK, 14_863_650);
    }

    #[test]
    fn MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK_constant_has_correct_value() {
        assert_eq!(MUMBAI_TESTNET_CONTRACT_CREATION_BLOCK, 24_638_838);
    }

    #[test]
    fn CONFIGURATOR_PREFIX_constant_has_correct_value() {
        assert_eq!(CONFIGURATOR_PREFIX, 0x0001_0000_0000_0000);
    }

    #[test]
    fn CONFIGURATOR_READ_ERROR_constant_has_correct_value() {
        assert_eq!(CONFIGURATOR_READ_ERROR, CONFIGURATOR_PREFIX | 1);
    }

    #[test]
    fn CONFIGURATOR_WRITE_ERROR_constant_has_correct_value() {
        assert_eq!(CONFIGURATOR_WRITE_ERROR, CONFIGURATOR_PREFIX | 2);
    }

    #[test]
    fn UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR_constant_has_correct_value() {
        assert_eq!(
            UNRECOGNIZED_MNEMONIC_LANGUAGE_ERROR,
            CONFIGURATOR_PREFIX | 3
        );
    }

    #[test]
    fn ILLEGAL_MNEMONIC_WORD_COUNT_ERROR_constant_has_correct_value() {
        assert_eq!(ILLEGAL_MNEMONIC_WORD_COUNT_ERROR, CONFIGURATOR_PREFIX | 4);
    }

    #[test]
    fn KEY_PAIR_CONSTRUCTION_ERROR_constant_has_correct_value() {
        assert_eq!(KEY_PAIR_CONSTRUCTION_ERROR, CONFIGURATOR_PREFIX | 5);
    }

    #[test]
    fn BAD_PASSWORD_ERROR_constant_has_correct_value() {
        assert_eq!(BAD_PASSWORD_ERROR, CONFIGURATOR_PREFIX | 6);
    }

    #[test]
    fn ALREADY_INITIALIZED_ERROR_constant_has_correct_value() {
        assert_eq!(ALREADY_INITIALIZED_ERROR, CONFIGURATOR_PREFIX | 7);
    }

    #[test]
    fn DERIVATION_PATH_ERROR_constant_has_correct_value() {
        assert_eq!(DERIVATION_PATH_ERROR, CONFIGURATOR_PREFIX | 8);
    }

    #[test]
    fn MNEMONIC_PHRASE_ERROR_constant_has_correct_value() {
        assert_eq!(MNEMONIC_PHRASE_ERROR, CONFIGURATOR_PREFIX | 9);
    }

    #[test]
    fn EARLY_QUESTIONING_ABOUT_DATA_constant_has_correct_value() {
        assert_eq!(EARLY_QUESTIONING_ABOUT_DATA, CONFIGURATOR_PREFIX | 10);
    }

    #[test]
    fn UNRECOGNIZED_PARAMETER_constant_has_correct_value() {
        assert_eq!(UNRECOGNIZED_PARAMETER, CONFIGURATOR_PREFIX | 11);
    }

    #[test]
    fn NON_PARSABLE_VALUE_constant_has_correct_value() {
        assert_eq!(NON_PARSABLE_VALUE, CONFIGURATOR_PREFIX | 12);
    }

    #[test]
    fn MISSING_DATA_constant_has_correct_value() {
        assert_eq!(MISSING_DATA, CONFIGURATOR_PREFIX | 13);
    }

    #[test]
    fn UNKNOWN_ERROR_constant_has_correct_value() {
        assert_eq!(UNKNOWN_ERROR, CONFIGURATOR_PREFIX | 14);
    }

    #[test]
    fn UI_NODE_COMMUNICATION_PREFIX_constant_has_correct_value() {
        assert_eq!(UI_NODE_COMMUNICATION_PREFIX, 0x8000_0000_0000_0000);
    }

    #[test]
    fn NODE_LAUNCH_ERROR_constant_has_correct_value() {
        assert_eq!(NODE_LAUNCH_ERROR, UI_NODE_COMMUNICATION_PREFIX | 1);
    }

    #[test]
    fn NODE_NOT_RUNNING_ERROR_constant_has_correct_value() {
        assert_eq!(NODE_NOT_RUNNING_ERROR, UI_NODE_COMMUNICATION_PREFIX | 2);
    }

    #[test]
    fn NODE_ALREADY_RUNNING_ERROR_constant_has_correct_value() {
        assert_eq!(NODE_ALREADY_RUNNING_ERROR, UI_NODE_COMMUNICATION_PREFIX | 3);
    }

    #[test]
    fn UNMARSHAL_ERROR_constant_has_correct_value() {
        assert_eq!(UNMARSHAL_ERROR, UI_NODE_COMMUNICATION_PREFIX | 4);
    }

    #[test]
    fn SETUP_ERROR_constant_has_correct_value() {
        assert_eq!(SETUP_ERROR, UI_NODE_COMMUNICATION_PREFIX | 5);
    }

    #[test]
    fn TIMEOUT_ERROR_constant_has_correct_value() {
        assert_eq!(TIMEOUT_ERROR, UI_NODE_COMMUNICATION_PREFIX | 6);
    }

    #[test]
    fn CENTRAL_DELIMITER_constant_has_correct_value() {
        assert_eq!(CENTRAL_DELIMITER, '@');
    }

    #[test]
    fn CHAIN_IDENTIFIER_DELIMITER_constant_has_correct_value() {
        assert_eq!(CHAIN_IDENTIFIER_DELIMITER, ':');
    }

    #[test]
    fn MAINNET_constant_has_correct_value() {
        assert_eq!(MAINNET, "mainnet");
    }

    #[test]
    fn POLYGON_FAMILY_constant_has_correct_value() {
        assert_eq!(POLYGON_FAMILY, "polygon");
    }

    #[test]
    fn ETH_FAMILY_constant_has_correct_value() {
        assert_eq!(ETH_FAMILY, "eth");
    }

    #[test]
    fn LINK_constant_has_correct_value() {
        assert_eq!(LINK, '-');
    }

    #[test]
    fn POLYGON_MAINNET_FULL_IDENTIFIER_constant_has_correct_value() {
        assert_eq!(POLYGON_MAINNET_FULL_IDENTIFIER, "polygon-mainnet");
    }

    #[test]
    fn _constant_has_correct_value() {
        assert_eq!(POLYGON_MUMBAI_FULL_IDENTIFIER, "polygon-mumbai");
    }

    #[test]
    fn DEV_CHAIN_FULL_IDENTIFIER_constant_has_correct_value() {
        assert_eq!(DEV_CHAIN_FULL_IDENTIFIER, "dev");
    }

    #[test]
    fn ETH_MAINNET_FULL_IDENTIFIER_constant_has_correct_value() {
        assert_eq!(ETH_MAINNET_FULL_IDENTIFIER, "eth-mainnet");
    }

    #[test]
    fn ETH_ROPSTEN_FULL_IDENTIFIER_constant_has_correct_value() {
        assert_eq!(ETH_ROPSTEN_FULL_IDENTIFIER, "eth-ropsten");
    }
}
