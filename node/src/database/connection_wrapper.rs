// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use rusqlite::{Connection, Error, Statement, Transaction};
use std::fmt::Debug;

#[cfg(test)]
use std::any::Any;

pub trait ConnectionWrapper: Debug + Send {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
    fn transaction<'a: 'b, 'b>(&'a mut self) -> Result<Transaction<'b>, rusqlite::Error>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        intentionally_blank!()
    }
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
    fn transaction<'a: 'b, 'b>(&'a mut self) -> Result<Transaction<'b>, Error> {
        self.conn.transaction()
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::{
        DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION,
    };
    use crate::db_config::config_dao::{ConfigDao, ConfigDaoRead, ConfigDaoReal};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn commit_works() {
        let data_dir = ensure_node_home_directory_exists("connection_wrapper", "commit_works");
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, Chain::from("dev"), true)
            .unwrap();
        let mut config_dao = ConfigDaoReal::new(conn);
        {
            let mut writer = config_dao.start_transaction().unwrap();
            writer
                .set("schema_version", Some("booga".to_string()))
                .unwrap();
            writer.commit().unwrap();
        }

        let result = config_dao.get("schema_version").unwrap().value_opt;

        assert_eq!(result, Some("booga".to_string()));
    }

    #[test]
    fn drop_works() {
        let data_dir = ensure_node_home_directory_exists("connection_wrapper", "drop_works");
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, Chain::from("dev"), true)
            .unwrap();
        let mut config_dao = ConfigDaoReal::new(conn);
        {
            let writer = config_dao.start_transaction().unwrap();
            writer
                .set("schema_version", Some("booga".to_string()))
                .unwrap();
        }

        let result = config_dao.get("schema_version").unwrap().value_opt;

        assert_eq!(result, Some(CURRENT_SCHEMA_VERSION.to_string()));
    }
}
