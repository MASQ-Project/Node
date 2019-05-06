// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use rusqlite::NO_PARAMS;
use rusqlite::{Connection, Statement};
use rusqlite::{Error, OpenFlags};
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;

pub const DATABASE_FILE: &str = "node_data.sqlite";
pub const CURRENT_SCHEMA_VERSION: &str = "0.0.1";

pub trait ConnectionWrapper: Debug {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        ConnectionWrapperReal { conn }
    }
}

#[derive(Debug, PartialEq)]
pub enum InitializationError {
    IncompatibleVersion,
    SqliteError,
}

pub trait DbInitializer {
    fn initialize(&self, path: &PathBuf) -> Result<Box<ConnectionWrapper>, InitializationError>;
}

pub struct DbInitializerReal {}

impl DbInitializer for DbInitializerReal {
    fn initialize(
        &self,
        path: &PathBuf,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let database_file_path = &path.join(DATABASE_FILE);
        match Connection::open_with_flags(database_file_path, flags) {
            Ok(conn) => {
                let config = self.extract_configurations(&conn);
                match self.check_version(config.get(&String::from("schema_version"))) {
                    Ok(_) => Ok(Box::new(ConnectionWrapperReal::new(conn))),
                    Err(e) => Err(e),
                }
            }
            Err(_) => {
                let mut flags = OpenFlags::empty();
                flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
                flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
                match Connection::open_with_flags(database_file_path, flags) {
                    Ok(conn) => match self.create_database_tables(&conn) {
                        Ok(()) => Ok(Box::new(ConnectionWrapperReal::new(conn))),
                        Err(e) => Err(e),
                    },
                    Err(_) => Err(InitializationError::SqliteError),
                }
            }
        }
    }
}

impl DbInitializerReal {
    pub fn new() -> DbInitializerReal {
        DbInitializerReal {}
    }

    fn create_database_tables(&self, conn: &Connection) -> Result<(), InitializationError> {
        self.create_config_table(conn)?;
        self.initialize_config(conn)?;
        self.create_payable_table(conn)?;
        self.create_receivable_table(conn)
    }

    fn create_config_table(&self, conn: &Connection) -> Result<(), InitializationError> {
        conn.execute(
            "create table config (
                name text not null,
                value text not null
            )",
            NO_PARAMS,
        )
        .expect("Can't create config table");
        conn.execute(
            "create unique index idx_config_name on config (name)",
            NO_PARAMS,
        )
        .expect("Can't create config name index");
        Ok(())
    }

    fn initialize_config(&self, conn: &Connection) -> Result<(), InitializationError> {
        conn.execute(
            format!(
                "insert into config (name, value) values ('schema_version', '{}')",
                CURRENT_SCHEMA_VERSION
            )
            .as_str(),
            NO_PARAMS,
        )
        .expect("Can't load config table");
        Ok(())
    }

    fn create_payable_table(&self, conn: &Connection) -> Result<(), InitializationError> {
        conn.execute(
            "create table payable (
                wallet_address text primary key,
                balance integer not null,
                last_paid_timestamp integer not null,
                pending_payment_transaction text null
            )",
            NO_PARAMS,
        )
        .expect("Can't create payable table");
        conn.execute(
            "create unique index idx_payable_wallet_address on payable (wallet_address)",
            NO_PARAMS,
        )
        .expect("Can't create payable wallet_address index");
        Ok(())
    }

    fn create_receivable_table(&self, conn: &Connection) -> Result<(), InitializationError> {
        conn.execute(
            "create table receivable (
                wallet_address text primary key,
                balance integer not null,
                last_received_timestamp integer not null
            )",
            NO_PARAMS,
        )
        .expect("Can't create receivable table");
        conn.execute(
            "create unique index idx_receivable_wallet_address on receivable (wallet_address)",
            NO_PARAMS,
        )
        .expect("Can't create receivable wallet_address index");
        Ok(())
    }

    fn extract_configurations(&self, conn: &Connection) -> HashMap<String, String> {
        let mut stmt = conn.prepare("select name, value from config").unwrap();
        let config_contents = stmt
            .query_map(NO_PARAMS, |row| Ok((row.get_unwrap(0), row.get_unwrap(1))))
            .expect("Internal error")
            .into_iter()
            .flat_map(|x| x);
        config_contents.collect::<HashMap<String, String>>()
    }

    fn check_version(&self, version: Option<&String>) -> Result<(), InitializationError> {
        match version {
            None => Err(InitializationError::IncompatibleVersion),
            Some(v_ref) => {
                if *v_ref == CURRENT_SCHEMA_VERSION {
                    Ok(())
                } else {
                    Err(InitializationError::IncompatibleVersion)
                }
            }
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::database::db_initializer::{ConnectionWrapper, DbInitializer, InitializationError};
    use rusqlite::Error;
    use rusqlite::Statement;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    pub struct ConnectionWrapperMock {}

    impl ConnectionWrapper for ConnectionWrapperMock {
        fn prepare(&self, _query: &str) -> Result<Statement, Error> {
            unimplemented!("Do not call prepare on a ConnectionWrapperMock")
        }
    }

    #[derive(Default)]
    pub struct DbInitializerMock {
        pub initialize_parameters: Arc<Mutex<Vec<PathBuf>>>,
        pub initialize_results: RefCell<Vec<Result<Box<ConnectionWrapper>, InitializationError>>>,
    }

    impl DbInitializer for DbInitializerMock {
        fn initialize(
            &self,
            path: &PathBuf,
        ) -> Result<Box<ConnectionWrapper>, InitializationError> {
            self.initialize_parameters
                .lock()
                .unwrap()
                .push(path.clone());
            self.initialize_results.borrow_mut().remove(0)
        }
    }

    impl DbInitializerMock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn initialize_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<PathBuf>>>,
        ) -> DbInitializerMock {
            self.initialize_parameters = parameters;
            self
        }

        pub fn initialize_result(
            self,
            result: Result<Box<ConnectionWrapper>, InitializationError>,
        ) -> DbInitializerMock {
            self.initialize_results.borrow_mut().push(result);
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::test_utils::ensure_node_home_directory_exists;
    use rusqlite::OpenFlags;

    #[test]
    fn nonexistent_database_is_created() {
        let home_dir = ensure_node_home_directory_exists("nonexistent_database_is_created");
        let subject = DbInitializerReal::new();

        subject.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let mut stmt = conn.prepare("select name, value from config").unwrap();
        let mut payable_contents = stmt
            .query_map(NO_PARAMS, |row| Ok((row.get_unwrap(0), row.get_unwrap(1))))
            .unwrap();
        assert_eq!(
            payable_contents.next().unwrap().unwrap(),
            (
                String::from("schema_version"),
                String::from(CURRENT_SCHEMA_VERSION)
            )
        );
        assert!(payable_contents.next().is_none());
        let mut stmt = conn.prepare ("select wallet_address, balance, last_paid_timestamp, pending_payment_transaction from payable").unwrap ();
        let mut payable_contents = stmt.query_map(NO_PARAMS, |_| Ok(42)).unwrap();
        assert!(payable_contents.next().is_none());
        let mut stmt = conn
            .prepare("select wallet_address, balance, last_received_timestamp from receivable")
            .unwrap();
        let mut receivable_contents = stmt.query_map(NO_PARAMS, |_| Ok(42)).unwrap();
        assert!(receivable_contents.next().is_none());
    }

    #[test]
    fn existing_database_with_correct_version_is_accepted_without_changes() {
        let home_dir =
            ensure_node_home_directory_exists("existing_database_with_version_is_accepted");
        let subject = DbInitializerReal::new();
        {
            DbInitializerReal::new().initialize(&home_dir).unwrap();
        }
        {
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute(
                "insert into config (name, value) values ('preexisting', 'yes')",
                NO_PARAMS,
            )
            .unwrap();
        }

        subject.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let mut stmt = conn
            .prepare("select name, value from config order by name")
            .unwrap();
        let mut config_contents = stmt
            .query_map(NO_PARAMS, |row| Ok((row.get_unwrap(0), row.get_unwrap(1))))
            .unwrap();
        assert_eq!(
            config_contents.next().unwrap().unwrap(),
            (String::from("preexisting"), String::from("yes"))
        );
        assert_eq!(
            config_contents.next().unwrap().unwrap(),
            (String::from("schema_version"), String::from("0.0.1"))
        );
        assert!(config_contents.next().is_none());
    }

    #[test]
    fn existing_database_with_no_version_is_rejected() {
        let home_dir =
            ensure_node_home_directory_exists("existing_database_with_no_version_is_rejected");
        {
            DbInitializerReal::new().initialize(&home_dir).unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute(
                "delete from config where name = 'schema_version'",
                NO_PARAMS,
            )
            .unwrap();
        }
        let subject = DbInitializerReal::new();

        let result = subject.initialize(&home_dir);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::IncompatibleVersion
        );
    }

    #[test]
    fn existing_database_with_the_wrong_version_is_rejected() {
        let home_dir = ensure_node_home_directory_exists(
            "existing_database_with_the_wrong_version_is_rejected",
        );
        {
            DbInitializerReal::new().initialize(&home_dir).unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute(
                "update config set value = '0.0.0' where name = 'schema_version'",
                NO_PARAMS,
            )
            .unwrap();
        }
        let subject = DbInitializerReal::new();

        let result = subject.initialize(&home_dir);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::IncompatibleVersion
        );
    }
}
