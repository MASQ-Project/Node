// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use crate::blockchain::errors::blockchain_loggable_error::BlockchainLoggableError;
use crate::blockchain::errors::custom_common_methods::CustomCommonMethods;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, PartialEq, Clone)]
pub enum MASQError {
    PendingTooLongNotReplaced,
}

impl BlockchainLoggableError for MASQError {
    fn as_common_methods(&self) -> &dyn CustomCommonMethods<Box<dyn BlockchainLoggableError>> {
        self
    }

    fn downgrade(&self) -> Box<dyn BlockchainDbError> {
        todo!()
    }
}

impl CustomCommonMethods<Box<dyn BlockchainLoggableError>> for MASQError {
    fn partial_eq(&self, other: &Box<dyn BlockchainLoggableError>) -> bool {
        todo!()
    }

    fn dup(&self) -> Box<dyn BlockchainLoggableError> {
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
    use crate::blockchain::errors::blockchain_loggable_error::BlockchainLoggableError;
    use crate::blockchain::errors::test_utils::test_clone_impl_for_blockchain_error;

    #[test]
    fn clone_works_for_blockchain_error_wrapping_masq_error() {
        let subject: Box<dyn BlockchainLoggableError> = Box::new(MASQError::PendingTooLongNotReplaced);

        test_clone_impl_for_blockchain_error::<MASQError>(subject);
    }

    #[test]
    fn display_for_blockchain_error_object_works() {
        vec![MASQError::PendingTooLongNotReplaced]
            .into_iter()
            .for_each(|error| {
                let wrapped_as_trait_object: Box<dyn BlockchainLoggableError> = Box::new(error.clone());
                assert_eq!(wrapped_as_trait_object.to_string(), format!("{:?}", error));
            })
    }
}
