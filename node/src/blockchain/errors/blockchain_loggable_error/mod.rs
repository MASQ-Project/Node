// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use crate::blockchain::errors::common_methods::CommonMethods;
use std::fmt::{Debug, Display};

pub mod app_rpc_web3_error;
pub mod masq_error;

// The Display impl is meant to be used for logging purposes.
pub trait BlockchainLoggableError: Display + Debug {
    fn as_common_methods(&self) -> &dyn CommonMethods<Box<dyn BlockchainLoggableError>>;
    fn downgrade(&self) -> Box<dyn BlockchainDbError>;
}

impl From<Box<dyn BlockchainLoggableError>> for Box<dyn BlockchainDbError> {
    fn from(more_verbose_error: Box<dyn BlockchainLoggableError>) -> Self {
        more_verbose_error.downgrade()
    }
}

impl Clone for Box<dyn BlockchainLoggableError> {
    fn clone(&self) -> Self {
        self.as_common_methods().dup()
    }
}

impl PartialEq for Box<dyn BlockchainLoggableError> {
    fn eq(&self, other: &Self) -> bool {
        self.as_common_methods().partial_eq(other)
    }
}

impl Eq for Box<dyn BlockchainLoggableError> {}
