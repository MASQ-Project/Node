// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use crate::combined_parameters::{PaymentCurves, RatePack, ScanIntervals};
use const_format::concatcp;
use lazy_static::lazy_static;
use std::time::Duration;

pub const DEFAULT_CHAIN: Chain = Chain::EthMainnet;

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

//payment curves, rate pack, scan intervals
const SECONDS_PER_DAY: i64 = 86_400;

lazy_static! {
    pub static ref DEFAULT_PAYMENT_CURVES: PaymentCurves = PaymentCurves {
        balance_decreases_for_sec: 30 * SECONDS_PER_DAY,
        balance_to_decrease_from_gwei: 1_000_000_000,
        payment_grace_before_ban_sec: SECONDS_PER_DAY,
        payment_suggested_after_sec: SECONDS_PER_DAY,
        permanent_debt_allowed_gwei: 10_000_000,
        unban_when_balance_below_gwei: 10_000_000,
    };
}

pub const DEFAULT_RATE_PACK: RatePack = RatePack {
    routing_byte_rate: 100,
    routing_service_rate: 10000,
    exit_byte_rate: 101,
    exit_service_rate: 10001,
};

pub const ZERO_RATE_PACK: RatePack = RatePack {
    routing_byte_rate: 0,
    routing_service_rate: 0,
    exit_byte_rate: 0,
    exit_service_rate: 0,
};

lazy_static! {
    pub static ref DEFAULT_SCAN_INTERVALS: ScanIntervals = ScanIntervals {
        pending_payable_scan_interval: Duration::from_secs(3600),
        payable_scan_interval: Duration::from_secs(3600),
        receivable_scan_interval: Duration::from_secs(3600)
    };
}

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
