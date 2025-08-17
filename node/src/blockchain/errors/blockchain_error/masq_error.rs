// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use crate::blockchain::errors::blockchain_error::BlockchainError;
use crate::blockchain::errors::custom_common_methods::CustomCommonMethods;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, PartialEq, Clone)]
pub enum MASQError {
    PendingTooLongNotReplaced,
}

impl BlockchainError for MASQError {
    fn as_common_methods(&self) -> &dyn CustomCommonMethods<Box<dyn BlockchainError>> {
        self
    }

    fn downgrade(&self) -> Box<dyn BlockchainDbError> {
        todo!()
    }
}

impl CustomCommonMethods<Box<dyn BlockchainError>> for MASQError {
    fn partial_eq(&self, other: &Box<dyn BlockchainError>) -> bool {
        todo!()
    }

    fn dup(&self) -> Box<dyn BlockchainError> {
        Box::new(self.clone())
    }

    as_any_ref_in_trait_impl!();
}

impl Display for MASQError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::errors::blockchain_error::app_rpc_web3_error::{
        AppRpcWeb3Error, LocalError, RemoteError,
    };
    use crate::blockchain::errors::blockchain_error::BlockchainError;
    use crate::blockchain::errors::test_utils::test_clone_impl_for_blockchain_error;
    use std::fmt::format;

    #[test]
    fn clone_works_for_blockchain_error_wrapping_masq_error() {
        let subject: Box<dyn BlockchainError> = Box::new(MASQError::PendingTooLongNotReplaced);

        test_clone_impl_for_blockchain_error::<MASQError>(subject);
    }

    #[test]
    fn display_for_blockchain_error_object_works() {
        vec![MASQError::PendingTooLongNotReplaced]
            .into_iter()
            .for_each(|error| {
                let wrapped_as_trait_object: Box<dyn BlockchainError> = Box::new(error.clone());
                assert_eq!(wrapped_as_trait_object.to_string(), format!("{:?}", error));
            })
    }
}
