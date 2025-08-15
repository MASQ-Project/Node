// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::utils::TxHash;
use web3::types::Address;

pub mod banned_dao;
pub mod failed_payable_dao;
pub mod payable_dao;
pub mod pending_payable_dao;
pub mod receivable_dao;
pub mod sent_payable_dao;
pub mod test_utils;
pub mod utils;

pub trait Transaction {
    fn hash(&self) -> TxHash;
    fn receiver_address(&self) -> Address;
    fn amount(&self) -> u128;
    fn timestamp(&self) -> i64;
    fn gas_price_wei(&self) -> u128;
    fn nonce(&self) -> u64;
    fn is_failed(&self) -> bool;
}
