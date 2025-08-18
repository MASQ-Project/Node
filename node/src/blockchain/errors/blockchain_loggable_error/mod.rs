// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use crate::blockchain::errors::custom_common_methods::CustomCommonMethods;
use std::fmt::{Debug, Display};

pub mod app_rpc_web3_error;
pub mod masq_error;

// The Display impl is meant to be used for logging purposes.
pub trait BlockchainLoggableError: Display + Debug {
    fn as_common_methods(&self) -> &dyn CustomCommonMethods<Box<dyn BlockchainLoggableError>>;
    fn downgrade(&self) -> Box<dyn BlockchainDbError>;
}

impl Clone for Box<dyn BlockchainLoggableError> {
    fn clone(&self) -> Self {
        self.as_common_methods().dup()
    }
}

impl PartialEq for Box<dyn BlockchainLoggableError> {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl Eq for Box<dyn BlockchainLoggableError> {}
