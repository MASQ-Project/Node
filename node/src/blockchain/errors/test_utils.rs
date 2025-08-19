// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::{BlockchainDbError, CustomHash, CustomSeDe};
use crate::blockchain::errors::blockchain_loggable_error::BlockchainLoggableError;
use crate::blockchain::errors::common_methods::CommonMethods;
use serde::de::{Error, Unexpected};
use serde_json::Value;
use std::fmt::Debug;
use std::hash::Hasher;

macro_rules! test_clone_impl {
    ($test_fn_name: ident, $boxed_trait: ident) => {
        pub fn $test_fn_name<ErrorType>(subject: Box<dyn $boxed_trait>)
        where
            ErrorType: PartialEq + Debug + 'static,
        {
            let result = subject.clone();

            let specified_subject = subject
                .as_common_methods()
                .as_any()
                .downcast_ref::<ErrorType>()
                .unwrap();
            let specified_result = result
                .as_common_methods()
                .as_any()
                .downcast_ref::<ErrorType>()
                .unwrap();
            assert_eq!(specified_result, specified_subject)
        }
    };
}

test_clone_impl!(test_clone_impl_for_blockchain_db_error, BlockchainDbError);
test_clone_impl!(
    test_clone_impl_for_blockchain_error,
    BlockchainLoggableError
);

#[derive(Debug, Default)]
pub struct BlockchainDbErrorMock {}

impl BlockchainDbError for BlockchainDbErrorMock {
    fn as_common_methods(&self) -> &dyn CommonMethods<Box<dyn BlockchainDbError>> {
        unimplemented!("not needed for testing")
    }
}

impl CustomSeDe for BlockchainDbErrorMock {
    fn custom_serialize(&self) -> Result<Value, serde_json::error::Error> {
        Err(serde_json::Error::invalid_type(
            Unexpected::Char('a'),
            &"null",
        ))
    }

    fn custom_deserialize(
        _str: &str,
    ) -> Result<Box<dyn BlockchainDbError>, serde_json::error::Error>
    where
        Self: Sized,
    {
        unimplemented!("not needed for testing")
    }
}

impl CustomHash for BlockchainDbErrorMock {
    fn custom_hash(&self, _hasher: &mut dyn Hasher) {
        unimplemented!("not needed for testing")
    }
}

impl CommonMethods<Box<dyn BlockchainDbError>> for BlockchainDbErrorMock {
    fn partial_eq(&self, _other: &Box<dyn BlockchainDbError>) -> bool {
        unimplemented!("not needed for testing")
    }

    fn clone_boxed(&self) -> Box<dyn BlockchainDbError> {
        unimplemented!("not needed for testing")
    }
}
