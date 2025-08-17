// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use std::fmt::Debug;

pub fn test_clone_for_blockchain_db_error<ErrorType>(subject: Box<dyn BlockchainDbError>)
where
    ErrorType: PartialEq + Debug + 'static,
{
    let result = subject.clone();

    let specified_subject = subject.as_any().downcast_ref::<ErrorType>().unwrap();
    let specified_result = result.as_any().downcast_ref::<ErrorType>().unwrap();
    assert_eq!(specified_result, specified_subject)
}
