// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
pub mod config_dumper;
pub mod connection_wrapper;
pub mod dao_utils;
pub mod db_initializer;
pub mod db_migrations;

#[derive(Debug, PartialEq, Clone)]
pub enum MappingProtocol {
    Pmp,
    Pcp,
    Igdp,
}

impl From<String> for MappingProtocol {
    fn from(val: String) -> Self {
        match val.as_str() {
            "1" => Self::Pmp,
            "2" => Self::Pcp,
            "3" => Self::Igdp,
            _ => panic!("something is wrong"),
        }
    }
}

impl From<MappingProtocol> for String {
    fn from(val: MappingProtocol) -> Self {
        match val {
            MappingProtocol::Pmp => "1".to_string(),
            MappingProtocol::Pcp => "2".to_string(),
            MappingProtocol::Igdp => "3".to_string(),
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::database::connection_wrapper::ConnectionWrapper;
    use crate::database::db_migrations::DbMigrator;
    use rusqlite::{Connection, NO_PARAMS};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct DbMigratorMock {
        migrate_database_result: RefCell<Vec<Result<(), String>>>,
        migrate_database_params: RefCell<Arc<Mutex<Vec<(String, Box<dyn ConnectionWrapper>)>>>>,
    }

    impl DbMigratorMock {
        pub fn migrate_database_result(self, result: Result<(), String>) -> Self {
            self.migrate_database_result.borrow_mut().push(result);
            self
        }
        pub fn migrate_database_params(
            self,
            result: Arc<Mutex<Vec<(String, Box<dyn ConnectionWrapper>)>>>,
        ) -> Self {
            self.migrate_database_params.replace(result);
            self
        }
    }

    impl DbMigrator for DbMigratorMock {
        fn migrate_database(
            &self,
            outdated_schema: &str,
            conn: Box<dyn ConnectionWrapper>,
        ) -> Result<(), String> {
            self.migrate_database_params
                .borrow_mut()
                .lock()
                .unwrap()
                .push((outdated_schema.to_string(), conn));
            self.migrate_database_result.borrow_mut().pop().unwrap()
        }
    }

    pub fn assurance_query_for_config_table(
        conn: &Connection,
        stm: &str,
    ) -> (String, Option<String>, u16) {
        conn.query_row(stm, NO_PARAMS, |r| {
            Ok((r.get(0).unwrap(), r.get(1).unwrap(), r.get(2).unwrap()))
        })
        .unwrap()
    }
}

#[cfg(test)]
mod test_mod {
    use crate::database::MappingProtocol;

    #[test]
    fn from_str_to_pmp_matches_correctly() {
        let result: MappingProtocol = "1".to_string().into();

        assert_eq!(result, MappingProtocol::Pmp)
    }

    #[test]
    fn from_str_to_pcp_matches_correctly() {
        let result: MappingProtocol = "2".to_string().into();

        assert_eq!(result, MappingProtocol::Pcp)
    }

    #[test]
    fn from_str_to_igdp_matches_correctly() {
        let result: MappingProtocol = "3".to_string().into();

        assert_eq!(result, MappingProtocol::Igdp)
    }

    #[test]
    #[should_panic(expected = "something is wrong")]
    fn lower_number_should_panic() {
        let _: MappingProtocol = "0".to_string().into();
    }

    #[test]
    #[should_panic(expected = "something is wrong")]
    fn higher_number_should_panic() {
        let _: MappingProtocol = "4".to_string().into();
    }

    #[test]
    fn from_pmp_to_str_matches_correctly() {
        let result: MappingProtocol = "1".to_string().into();

        assert_eq!(result, MappingProtocol::Pmp)
    }

    #[test]
    fn from_pcp_to_str_matches_correctly() {
        let result: MappingProtocol = "2".to_string().into();

        assert_eq!(result, MappingProtocol::Pcp)
    }

    #[test]
    fn from_igdp_to_str_matches_correctly() {
        let result: MappingProtocol = "3".to_string().into();

        assert_eq!(result, MappingProtocol::Igdp)
    }
}
