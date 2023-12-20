// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_big_integer::big_int_db_processor::{
    BigIntDatabaseError, BigIntDbProcessor, BigIntSqlConfig, TableNameDAO,
};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionSecureWrapper};
use itertools::Either;
use std::cell::RefCell;

pub(in crate::accountant::db_big_integer) mod restricted {
    use crate::accountant::db_big_integer::big_int_db_processor::KeyVariants::TestKey;
    use crate::accountant::db_big_integer::big_int_db_processor::{
        DisplayableParamValue, KeyVariants,
    };
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection;

    pub fn create_new_empty_db(module: &str, test_name: &str) -> Connection {
        let home_dir = ensure_node_home_directory_exists(module, test_name);
        let db_path = home_dir.join("test_table.db");
        Connection::open(db_path.as_path()).unwrap()
    }

    pub fn test_database_key<'a>(val: &'a dyn DisplayableParamValue) -> KeyVariants<'a> {
        TestKey {
            column_name: "name",
            substitution_name: ":name",
            value: val,
        }
    }
}

#[derive(Default, Debug)]
pub struct BigIntDbProcessorMock {
    execute_results: RefCell<Vec<Result<(), BigIntDatabaseError>>>,
}

impl<T> BigIntDbProcessor<T> for BigIntDbProcessorMock
where
    T: TableNameDAO,
{
    fn execute<'a>(
        &self,
        _conn: Either<&dyn ConnectionWrapper, &TransactionSecureWrapper>,
        _config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDatabaseError> {
        // You can implement a params capture here but so far it hasn't been needed,
        // we've done well with testing on the prod code
        self.execute_results.borrow_mut().remove(0)
    }
}

impl BigIntDbProcessorMock {
    pub fn execute_result(self, result: Result<(), BigIntDatabaseError>) -> Self {
        self.execute_results.borrow_mut().push(result);
        self
    }
}
