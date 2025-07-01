// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use crate::data_version::DataVersion;
use const_format::concatcp;

pub const DEFAULT_CHAIN: Chain = Chain::PolyMainnet;
pub const CURRENT_SCHEMA_VERSION: usize = 11;

pub const HIGHEST_RANDOM_CLANDESTINE_PORT: u16 = 9999;
pub const HTTP_PORT: u16 = 80;
pub const TLS_PORT: u16 = 443;
pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;
pub const DEFAULT_UI_PORT: u16 = 5333;

pub const MASQ_URL_PREFIX: &str = "masq://";
pub const CURRENT_LOGFILE_NAME: &str = "MASQNode_rCURRENT.log";
pub const MASQ_PROMPT: &str = "masq> ";

pub const DEFAULT_GAS_PRICE: u64 = 1; //TODO ?? Really
pub const DEFAULT_GAS_PRICE_MARGIN: u64 = 30;

pub const WALLET_ADDRESS_LENGTH: usize = 42;
pub const MASQ_TOTAL_SUPPLY: u64 = 37_500_000;
pub const WEIS_IN_GWEI: i128 = 1_000_000_000;

pub const DEFAULT_MAX_BLOCK_COUNT: u64 = 100_000;

pub const PAYLOAD_ZERO_SIZE: usize = 0usize;

pub const ETH_MAINNET_CONTRACT_CREATION_BLOCK: u64 = 11_170_708;
pub const ETH_ROPSTEN_CONTRACT_CREATION_BLOCK: u64 = 8_688_171;
pub const POLYGON_MAINNET_CONTRACT_CREATION_BLOCK: u64 = 14_863_650;
pub const POLYGON_AMOY_CONTRACT_CREATION_BLOCK: u64 = 5_323_366;
pub const BASE_MAINNET_CONTRACT_CREATION_BLOCK: u64 = 19_711_235;
pub const BASE_SEPOLIA_CONTRACT_CREATION_BLOCK: u64 = 14_732_730;
pub const MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK: u64 = 0;

//Migration versions
////////////////////////////////////////////////////////////////////////////////////////////////////

// If you're adding a new constant here,
// please add it to the test: check_limits_of_data_versions_const()
pub const CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION: DataVersion = DataVersion { major: 0, minor: 1 };
pub const CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION: DataVersion = DataVersion { major: 0, minor: 1 };
pub const DNS_RESOLVER_FAILURE_CURRENT_VERSION: DataVersion = DataVersion { major: 0, minor: 1 };
pub const GOSSIP_CURRENT_VERSION: DataVersion = DataVersion { major: 0, minor: 1 };
pub const GOSSIP_FAILURE_CURRENT_VERSION: DataVersion = DataVersion { major: 0, minor: 1 };
pub const NODE_RECORD_INNER_CURRENT_VERSION: DataVersion = DataVersion { major: 0, minor: 1 };

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
pub const SCAN_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 7;
pub const EXIT_COUNTRY_MISSING_COUNTRIES_ERROR: u64 = UI_NODE_COMMUNICATION_PREFIX | 8;

//accountant
pub const ACCOUNTANT_PREFIX: u64 = 0x0040_0000_0000_0000;
pub const REQUEST_WITH_NO_VALUES: u64 = ACCOUNTANT_PREFIX | 1;
pub const REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS: u64 = ACCOUNTANT_PREFIX | 2;
pub const VALUE_EXCEEDS_ALLOWED_LIMIT: u64 = ACCOUNTANT_PREFIX | 3;

////////////////////////////////////////////////////////////////////////////////////////////////////

pub const COMBINED_PARAMETERS_DELIMITER: char = '|';

//descriptor
pub const CENTRAL_DELIMITER: char = '@';
pub const CHAIN_IDENTIFIER_DELIMITER: char = ':';

//chains
pub const POLYGON_MAINNET_CHAIN_ID: u64 = 137;
pub const POLYGON_AMOY_CHAIN_ID: u64 = 80002;
pub const BASE_MAINNET_CHAIN_ID: u64 = 8453;
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;
pub const ETH_MAINNET_CHAIN_ID: u64 = 1;
pub const ETH_ROPSTEN_CHAIN_ID: u64 = 3;
pub const DEV_CHAIN_ID: u64 = 2;
const POLYGON_FAMILY: &str = "polygon";
const ETH_FAMILY: &str = "eth";
const BASE_FAMILY: &str = "base";
const MAINNET: &str = "mainnet";
const LINK: char = '-';
pub const POLYGON_MAINNET_FULL_IDENTIFIER: &str = concatcp!(POLYGON_FAMILY, LINK, MAINNET);
pub const POLYGON_AMOY_FULL_IDENTIFIER: &str = concatcp!(POLYGON_FAMILY, LINK, "amoy");
pub const ETH_MAINNET_FULL_IDENTIFIER: &str = concatcp!(ETH_FAMILY, LINK, MAINNET);
pub const ETH_ROPSTEN_FULL_IDENTIFIER: &str = concatcp!(ETH_FAMILY, LINK, "ropsten");
pub const BASE_MAINNET_FULL_IDENTIFIER: &str = concatcp!(BASE_FAMILY, LINK, MAINNET);
pub const BASE_SEPOLIA_FULL_IDENTIFIER: &str = concatcp!(BASE_FAMILY, LINK, "sepolia");
pub const DEV_CHAIN_FULL_IDENTIFIER: &str = "dev";
pub const POLYGON_GAS_PRICE_CEILING_WEI: u128 = 200_000_000_000;
pub const ETH_GAS_PRICE_CEILING_WEI: u128 = 100_000_000_000;
pub const BASE_GAS_PRICE_CEILING_WEI: u128 = 50_000_000_000;
pub const DEV_GAS_PRICE_CEILING_WEI: u128 = 200_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(DEFAULT_CHAIN, Chain::PolyMainnet);
        assert_eq!(HIGHEST_RANDOM_CLANDESTINE_PORT, 9999);
        assert_eq!(HTTP_PORT, 80);
        assert_eq!(TLS_PORT, 443);
        assert_eq!(LOWEST_USABLE_INSECURE_PORT, 1025);
        assert_eq!(HIGHEST_USABLE_PORT, 65535);
        assert_eq!(DEFAULT_UI_PORT, 5333);
        assert_eq!(MASQ_URL_PREFIX, "masq://");
        assert_eq!(CURRENT_LOGFILE_NAME, "MASQNode_rCURRENT.log");
        assert_eq!(MASQ_PROMPT, "masq> ");
        assert_eq!(DEFAULT_GAS_PRICE, 1);
        assert_eq!(DEFAULT_GAS_PRICE_MARGIN, 30);
        assert_eq!(WALLET_ADDRESS_LENGTH, 42);
        assert_eq!(MASQ_TOTAL_SUPPLY, 37_500_000);
        assert_eq!(WEIS_IN_GWEI, 1_000_000_000);
        assert_eq!(ETH_MAINNET_CONTRACT_CREATION_BLOCK, 11_170_708);
        assert_eq!(ETH_ROPSTEN_CONTRACT_CREATION_BLOCK, 8_688_171);
        assert_eq!(POLYGON_MAINNET_CONTRACT_CREATION_BLOCK, 14_863_650);
        assert_eq!(POLYGON_AMOY_CONTRACT_CREATION_BLOCK, 5_323_366);
        assert_eq!(BASE_MAINNET_CONTRACT_CREATION_BLOCK, 19_711_235);
        assert_eq!(BASE_SEPOLIA_CONTRACT_CREATION_BLOCK, 14_732_730);
        assert_eq!(MULTINODE_TESTNET_CONTRACT_CREATION_BLOCK, 0);
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
        assert_eq!(SCAN_ERROR, UI_NODE_COMMUNICATION_PREFIX | 7);
        assert_eq!(ACCOUNTANT_PREFIX, 0x0040_0000_0000_0000);
        assert_eq!(REQUEST_WITH_NO_VALUES, ACCOUNTANT_PREFIX | 1);
        assert_eq!(
            REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS,
            ACCOUNTANT_PREFIX | 2
        );
        assert_eq!(VALUE_EXCEEDS_ALLOWED_LIMIT, ACCOUNTANT_PREFIX | 3);
        assert_eq!(CENTRAL_DELIMITER, '@');
        assert_eq!(CHAIN_IDENTIFIER_DELIMITER, ':');
        assert_eq!(POLYGON_MAINNET_CHAIN_ID, 137);
        assert_eq!(POLYGON_AMOY_CHAIN_ID, 80002);
        assert_eq!(BASE_MAINNET_CHAIN_ID, 8453);
        assert_eq!(BASE_SEPOLIA_CHAIN_ID, 84532);
        assert_eq!(ETH_MAINNET_CHAIN_ID, 1);
        assert_eq!(ETH_ROPSTEN_CHAIN_ID, 3);
        assert_eq!(DEV_CHAIN_ID, 2);
        assert_eq!(POLYGON_FAMILY, "polygon");
        assert_eq!(ETH_FAMILY, "eth");
        assert_eq!(BASE_FAMILY, "base");
        assert_eq!(MAINNET, "mainnet");
        assert_eq!(LINK, '-');
        assert_eq!(POLYGON_MAINNET_FULL_IDENTIFIER, "polygon-mainnet");
        assert_eq!(POLYGON_AMOY_FULL_IDENTIFIER, "polygon-amoy");
        assert_eq!(ETH_MAINNET_FULL_IDENTIFIER, "eth-mainnet");
        assert_eq!(ETH_ROPSTEN_FULL_IDENTIFIER, "eth-ropsten");
        assert_eq!(BASE_SEPOLIA_FULL_IDENTIFIER, "base-sepolia");
        assert_eq!(DEV_CHAIN_FULL_IDENTIFIER, "dev");
        assert_eq!(POLYGON_GAS_PRICE_CEILING_WEI, 200_000_000_000);
        assert_eq!(ETH_GAS_PRICE_CEILING_WEI, 100_000_000_000);
        assert_eq!(BASE_GAS_PRICE_CEILING_WEI, 50_000_000_000);
        assert_eq!(DEV_GAS_PRICE_CEILING_WEI, 200_000_000_000);
        assert_eq!(
            CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION,
            DataVersion { major: 0, minor: 1 }
        );
        assert_eq!(
            CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION,
            DataVersion { major: 0, minor: 1 }
        );
        assert_eq!(
            DNS_RESOLVER_FAILURE_CURRENT_VERSION,
            DataVersion { major: 0, minor: 1 }
        );
        assert_eq!(GOSSIP_CURRENT_VERSION, DataVersion { major: 0, minor: 1 });
        assert_eq!(
            GOSSIP_FAILURE_CURRENT_VERSION,
            DataVersion { major: 0, minor: 1 }
        );
        assert_eq!(
            NODE_RECORD_INNER_CURRENT_VERSION,
            DataVersion { major: 0, minor: 1 }
        );
        assert_eq!(PAYLOAD_ZERO_SIZE, 0usize);
    }

    #[test]
    fn check_limits_of_data_versions_const() {
        [
            CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION,
            CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION,
            DNS_RESOLVER_FAILURE_CURRENT_VERSION,
            GOSSIP_CURRENT_VERSION,
            GOSSIP_FAILURE_CURRENT_VERSION,
            NODE_RECORD_INNER_CURRENT_VERSION,
        ]
        .into_iter()
        .for_each(|item| {
            assert!(item.major <= 4095);
            assert!(item.minor <= 4095);
        })
    }
}
