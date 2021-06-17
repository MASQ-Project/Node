// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::blockchain_interface::{
    chain_name_from_id, contract_creation_block_from_chain_id,
};
use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
use crate::db_config::secure_config_layer::EXAMPLE_ENCRYPTED;
use masq_lib::constants::{
    DEFAULT_GAS_PRICE, HIGHEST_RANDOM_CLANDESTINE_PORT, LOWEST_USABLE_INSECURE_PORT,
};
use rand::prelude::*;
use rusqlite::Error::InvalidColumnType;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use tokio::net::TcpListener;

pub const DATABASE_FILE: &str = "node-data.db";
pub const CURRENT_SCHEMA_VERSION: &str = "0.0.10";

#[derive(Debug, PartialEq)]
pub enum InitializationError {
    Nonexistent,
    IncompatibleVersion(String),
    SqliteError(rusqlite::Error),
}

pub trait DbInitializer {
    fn initialize(
        &self,
        path: &Path,
        chain_id: u8,
        create_if_necessary: bool,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError>;
}

#[derive(Default)]
pub struct DbInitializerReal {}

impl DbInitializer for DbInitializerReal {
    fn initialize(
        &self,
        path: &Path,
        chain_id: u8,
        create_if_necessary: bool,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        let is_creation_necessary = Self::is_creation_necessary(path);
        if !create_if_necessary && is_creation_necessary {
            return Err(InitializationError::Nonexistent);
        }
        Self::create_data_directory_if_necessary(path);
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let database_file_path = &path.join(DATABASE_FILE);
        match Connection::open_with_flags(database_file_path, flags) {
            Ok(conn) => {
                eprintln!("Opened existing database at {:?}", database_file_path);
                let config = self.extract_configurations(&conn);
                match self.check_version(config.get("schema_version")) {
                    Ok(_) => Ok(Box::new(ConnectionWrapperReal::new(conn))),
                    Err(e) => Err(e),
                }
            }
            Err(_) => {
                let mut flags = OpenFlags::empty();
                flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
                flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
                match Connection::open_with_flags(database_file_path, flags) {
                    Ok(conn) => {
                        eprintln!("Created new database at {:?}", database_file_path);
                        self.create_database_tables(&conn, chain_id);
                        Ok(Box::new(ConnectionWrapperReal::new(conn)))
                    }
                    Err(e) => Err(InitializationError::SqliteError(e)),
                }
            }
        }
    }
}

impl DbInitializerReal {
    pub fn new() -> Self {
        Self::default()
    }

    fn is_creation_necessary(data_directory: &Path) -> bool {
        match fs::read_dir(data_directory) {
            Ok(_) => !data_directory.join(DATABASE_FILE).exists(),
            Err(_) => true,
        }
    }

    fn create_data_directory_if_necessary(data_directory: &Path) {
        match fs::read_dir(data_directory) {
            Ok(_) => (),
            Err(ref e) if e.kind() == ErrorKind::NotFound => fs::create_dir_all(data_directory)
                .unwrap_or_else(|_| {
                    panic!(
                        "Cannot create specified data directory at {:?}",
                        data_directory
                    )
                }),
            Err(e) => panic!(
                "Error checking data directory at {:?}: {}",
                data_directory, e
            ),
        }
    }

    fn create_database_tables(&self, conn: &Connection, chain_id: u8) {
        self.create_config_table(conn);
        self.initialize_config(conn, chain_id);
        self.create_payable_table(conn);
        self.create_receivable_table(conn);
        self.create_banned_table(conn);
    }

    fn create_config_table(&self, conn: &Connection) {
        conn.execute(
            "create table if not exists config (
                name text not null,
                value text,
                encrypted integer not null
            )",
            NO_PARAMS,
        )
        .expect("Can't create config table");
        conn.execute(
            "create unique index if not exists idx_config_name on config (name)",
            NO_PARAMS,
        )
        .expect("Can't create config name index");
    }

    fn initialize_config(&self, conn: &Connection, chain_id: u8) {
        Self::set_config_value(conn, EXAMPLE_ENCRYPTED, None, true, "example_encrypted");
        Self::set_config_value(
            conn,
            "clandestine_port",
            Some(&Self::choose_clandestine_port().to_string()),
            false,
            "clandestine port",
        );
        Self::set_config_value(
            conn,
            "consuming_wallet_derivation_path",
            None,
            false,
            "consuming wallet derivation path",
        );
        Self::set_config_value(
            conn,
            "consuming_wallet_public_key",
            None,
            false,
            "public key for the consuming wallet private key",
        );
        Self::set_config_value(
            conn,
            "earning_wallet_address",
            None,
            false,
            "earning wallet address",
        );
        Self::set_config_value(
            conn,
            "schema_version",
            Some(CURRENT_SCHEMA_VERSION),
            false,
            "database version",
        );
        Self::set_config_value(conn, "seed", None, true, "mnemonic seed");
        Self::set_config_value(
            conn,
            "start_block",
            Some(&contract_creation_block_from_chain_id(chain_id).to_string()),
            false,
            format!("{} start block", chain_name_from_id(chain_id)).as_str(),
        );
        Self::set_config_value(
            conn,
            "gas_price",
            Some(DEFAULT_GAS_PRICE),
            false,
            "gas price",
        );
        Self::set_config_value(conn, "past_neighbors", None, true, "past neighbors");
    }

    fn create_payable_table(&self, conn: &Connection) {
        conn.execute(
            "create table if not exists payable (
                wallet_address text primary key,
                balance integer not null,
                last_paid_timestamp integer not null,
                pending_payment_transaction text null
            )",
            NO_PARAMS,
        )
        .expect("Can't create payable table");
        conn.execute(
            "create unique index if not exists idx_payable_wallet_address on payable (wallet_address)",
            NO_PARAMS,
        )
        .expect("Can't create payable wallet_address index");
    }

    fn create_receivable_table(&self, conn: &Connection) {
        conn.execute(
            "create table if not exists receivable (
                wallet_address text primary key,
                balance integer not null,
                last_received_timestamp integer not null
            )",
            NO_PARAMS,
        )
        .expect("Can't create receivable table");
        conn.execute(
            "create unique index if not exists idx_receivable_wallet_address on receivable (wallet_address)",
            NO_PARAMS,
        )
        .expect("Can't create receivable wallet_address index");
    }

    fn create_banned_table(&self, conn: &Connection) {
        conn.execute(
            "create table banned ( wallet_address text primary key )",
            NO_PARAMS,
        )
        .expect("Can't create banned table");
        conn.execute(
            "create unique index idx_banned_wallet_address on banned (wallet_address)",
            NO_PARAMS,
        )
        .expect("Can't create banned wallet_address index");
    }

    fn extract_configurations(&self, conn: &Connection) -> HashMap<String, Option<String>> {
        let mut stmt = conn.prepare("select name, value from config").unwrap();
        let query_result = stmt.query_map(NO_PARAMS, |row| Ok((row.get(0), row.get(1))));
        match query_result {
            Ok(rows) => rows,
            Err(e) => panic!("Error retrieving configuration: {}", e),
        }
        .map(|row| match row {
            Ok((Ok(name), Ok(value))) => (name, Some(value)),
            Ok((Ok(name), Err(InvalidColumnType(1, _, _)))) => (name, None),
            e => panic!("Error retrieving configuration: {:?}", e),
        })
        .collect::<HashMap<String, Option<String>>>()
    }

    fn check_version(&self, version: Option<&Option<String>>) -> Result<(), InitializationError> {
        match version {
            None => Err(InitializationError::IncompatibleVersion(format!(
                "Need {}, found nothing",
                CURRENT_SCHEMA_VERSION
            ))),
            Some(None) => Err(InitializationError::IncompatibleVersion(format!(
                "Need {}, found nothing",
                CURRENT_SCHEMA_VERSION
            ))),
            Some(Some(v_ref)) => {
                if *v_ref == CURRENT_SCHEMA_VERSION {
                    Ok(())
                } else {
                    Err(InitializationError::IncompatibleVersion(format!(
                        "Need {}, found {}",
                        CURRENT_SCHEMA_VERSION, v_ref
                    )))
                }
            }
        }
    }

    fn choose_clandestine_port() -> u16 {
        let mut rng = SmallRng::from_entropy();
        loop {
            let candidate_port: u16 =
                rng.gen_range(LOWEST_USABLE_INSECURE_PORT, HIGHEST_RANDOM_CLANDESTINE_PORT);
            match TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(0),
                candidate_port,
            ))) {
                Ok(_) => return candidate_port,
                Err(_) => continue,
            }
        }
    }

    fn set_config_value(
        conn: &Connection,
        name: &str,
        value: Option<&str>,
        encrypted: bool,
        readable: &str,
    ) {
        conn.execute(
            format!(
                "insert into config (name, value, encrypted) values ('{}', {}, {})",
                name,
                match value {
                    Some(value) => format!("'{}'", value),
                    None => "null".to_string(),
                },
                if encrypted { 1 } else { 0 }
            )
            .as_str(),
            NO_PARAMS,
        )
        .unwrap_or_else(|e| panic!("Can't preload config table with {}: {:?}", readable, e));
    }
}

pub fn connection_or_panic(
    db_initializer: &dyn DbInitializer,
    path: &Path,
    chain_id: u8,
    create_if_necessary: bool,
) -> Box<dyn ConnectionWrapper> {
    db_initializer
        .initialize(path, chain_id, create_if_necessary)
        .unwrap_or_else(|_| {
            panic!(
                "Failed to connect to database at {:?}",
                path.join(DATABASE_FILE)
            )
        })
}

#[cfg(test)]
pub mod test_utils {
    use crate::database::connection_wrapper::ConnectionWrapper;
    use crate::database::db_initializer::{DbInitializer, InitializationError};
    use rusqlite::Transaction;
    use rusqlite::{Error, Statement};
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    pub struct ConnectionWrapperMock<'a> {
        pub prepare_parameters: Arc<Mutex<Vec<String>>>,
        pub prepare_results: RefCell<Vec<Result<Statement<'a>, Error>>>,
        pub transaction_results: RefCell<Vec<Result<Transaction<'a>, Error>>>,
    }

    unsafe impl<'a> Send for ConnectionWrapperMock<'a> {}

    impl<'a> ConnectionWrapperMock<'a> {
        pub fn prepare_result(self, result: Result<Statement<'a>, Error>) -> Self {
            self.prepare_results.borrow_mut().push(result);
            self
        }

        pub fn transaction_result(self, result: Result<Transaction<'a>, Error>) -> Self {
            self.transaction_results.borrow_mut().push(result);
            self
        }
    }

    impl<'a> ConnectionWrapper for ConnectionWrapperMock<'a> {
        fn prepare(&self, query: &str) -> Result<Statement, Error> {
            self.prepare_parameters
                .lock()
                .unwrap()
                .push(String::from(query));
            self.prepare_results.borrow_mut().remove(0)
        }

        fn transaction<'x: 'y, 'y>(&'x mut self) -> Result<Transaction<'y>, Error> {
            self.transaction_results.borrow_mut().remove(0)
        }
    }

    #[derive(Default)]
    pub struct DbInitializerMock {
        pub initialize_parameters: Arc<Mutex<Vec<(PathBuf, u8, bool)>>>,
        pub initialize_results:
            RefCell<Vec<Result<Box<dyn ConnectionWrapper>, InitializationError>>>,
    }

    impl DbInitializer for DbInitializerMock {
        fn initialize(
            &self,
            path: &Path,
            chain_id: u8,
            create_if_necessary: bool,
        ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
            self.initialize_parameters.lock().unwrap().push((
                path.to_path_buf(),
                chain_id,
                create_if_necessary,
            ));
            self.initialize_results.borrow_mut().remove(0)
        }
    }

    impl DbInitializerMock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn initialize_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<(PathBuf, u8, bool)>>>,
        ) -> DbInitializerMock {
            self.initialize_parameters = parameters;
            self
        }

        pub fn initialize_result(
            self,
            result: Result<Box<dyn ConnectionWrapper>, InitializationError>,
        ) -> DbInitializerMock {
            self.initialize_results.borrow_mut().push(result);
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::chain_id_from_name;
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
        DEFAULT_CHAIN_ID, TEST_DEFAULT_CHAIN_NAME,
    };
    use rusqlite::types::Type::Null;
    use rusqlite::{Error, OpenFlags};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use tokio::net::TcpListener;

    #[test]
    fn db_initialize_does_not_create_if_directed_not_to_and_directory_does_not_exist() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_does_not_create_if_directed_not_to_and_directory_does_not_exist",
        );
        let subject = DbInitializerReal::new();

        let result = subject.initialize(&home_dir, DEFAULT_CHAIN_ID, false);

        assert_eq!(result.err().unwrap(), InitializationError::Nonexistent);
        let result = Connection::open(&home_dir.join(DATABASE_FILE));
        match result.err().unwrap() {
            Error::SqliteFailure(_, _) => (),
            x => panic!("Expected SqliteFailure, got {:?}", x),
        }
    }

    #[test]
    fn db_initialize_does_not_create_if_directed_not_to_and_database_file_does_not_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "db_initialize_does_not_create_if_directed_not_to_and_database_file_does_not_exist",
        );
        let subject = DbInitializerReal::new();

        let result = subject.initialize(&home_dir, DEFAULT_CHAIN_ID, false);

        assert_eq!(result.err().unwrap(), InitializationError::Nonexistent);
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let result = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags);
        match result.err().unwrap() {
            Error::SqliteFailure(_, _) => (),
            x => panic!("Expected SqliteFailure, got {:?}", x),
        }
    }

    #[test]
    fn db_initialize_creates_payable_table() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_payable_table",
        );
        let subject = DbInitializerReal::new();

        subject
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let mut stmt = conn.prepare ("select wallet_address, balance, last_paid_timestamp, pending_payment_transaction from payable").unwrap ();
        let mut payable_contents = stmt.query_map(NO_PARAMS, |_| Ok(42)).unwrap();
        assert!(payable_contents.next().is_none());
    }

    #[test]
    fn db_initialize_creates_receivable_table() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_receivable_table",
        );
        let subject = DbInitializerReal::new();

        subject
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let mut stmt = conn
            .prepare("select wallet_address, balance, last_received_timestamp from receivable")
            .unwrap();
        let mut receivable_contents = stmt.query_map(NO_PARAMS, |_| Ok(())).unwrap();
        assert!(receivable_contents.next().is_none());
    }

    #[test]
    fn db_initialize_creates_banned_table() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_creates_banned_table",
        );
        let subject = DbInitializerReal::new();

        subject
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let mut stmt = conn.prepare("select wallet_address from banned").unwrap();
        let mut banned_contents = stmt.query_map(NO_PARAMS, |_| Ok(42)).unwrap();
        assert!(banned_contents.next().is_none());
    }

    #[test]
    fn existing_database_with_correct_version_is_accepted_without_changes() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_version_is_accepted",
        );
        let subject = DbInitializerReal::new();
        {
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap();
        }
        {
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute(
                "insert into config (name, value, encrypted) values ('preexisting', 'yes', 0)",
                NO_PARAMS,
            )
            .unwrap();
        }

        subject
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let config_map = subject.extract_configurations(&conn);
        let mut config_vec: Vec<(String, Option<String>)> = config_map.into_iter().collect();
        config_vec.sort_by_key(|(name, _)| name.clone());
        let verify = |cv: &mut Vec<(String, Option<String>)>, name: &str, value: Option<&str>| {
            let actual = cv.remove(0);
            let expected = (name.to_string(), value.map(|v| v.to_string()));
            assert_eq!(actual, expected)
        };
        let verify_name = |cv: &mut Vec<(String, Option<String>)>, expected_name: &str| {
            let (actual_name, value) = cv.remove(0);
            assert_eq!(actual_name, expected_name);
            value
        };
        let clandestine_port_str_opt = verify_name(&mut config_vec, "clandestine_port");
        let clandestine_port: u16 = clandestine_port_str_opt.unwrap().parse().unwrap();
        assert!(clandestine_port >= 1025);
        assert!(clandestine_port < 10000);
        verify(&mut config_vec, "consuming_wallet_derivation_path", None);
        verify(&mut config_vec, "consuming_wallet_public_key", None);
        verify(&mut config_vec, "earning_wallet_address", None);
        verify(&mut config_vec, EXAMPLE_ENCRYPTED, None);
        verify(&mut config_vec, "gas_price", Some(DEFAULT_GAS_PRICE));
        verify(&mut config_vec, "past_neighbors", None);
        verify(&mut config_vec, "preexisting", Some("yes")); // makes sure we just created this database
        verify(
            &mut config_vec,
            "schema_version",
            Some(CURRENT_SCHEMA_VERSION),
        );
        verify(&mut config_vec, "seed", None);
        verify(
            &mut config_vec,
            "start_block",
            Some(&format!(
                "{}",
                contract_creation_block_from_chain_id(chain_id_from_name(TEST_DEFAULT_CHAIN_NAME))
            )),
        );
        assert_eq!(config_vec, vec![]);
    }

    #[test]
    fn existing_database_with_no_version_is_rejected() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_no_version_is_rejected",
        );
        {
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap();
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

        let result = subject.initialize(&home_dir, DEFAULT_CHAIN_ID, true);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::IncompatibleVersion(format!(
                "Need {}, found nothing",
                CURRENT_SCHEMA_VERSION
            )),
        );
    }

    #[test]
    fn existing_database_with_the_wrong_version_is_rejected() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_the_wrong_version_is_rejected",
        );
        {
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap();
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

        let result = subject.initialize(&home_dir, DEFAULT_CHAIN_ID, true);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::IncompatibleVersion(format!(
                "Need {}, found 0.0.0",
                CURRENT_SCHEMA_VERSION
            )),
        );
    }

    #[test]
    fn choose_clandestine_port_chooses_different_unused_ports_each_time() {
        let _listeners = (0..10)
            .map(|_| {
                let port = DbInitializerReal::choose_clandestine_port();
                TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), port)))
                    .expect(&format!("Port {} was not free", port))
            })
            .collect::<Vec<TcpListener>>();
    }

    #[test]
    fn choose_clandestine_port_chooses_ports_between_the_minimum_and_maximum() {
        let clandestine_port_value = DbInitializerReal::choose_clandestine_port();
        assert!(
            clandestine_port_value >= LOWEST_USABLE_INSECURE_PORT,
            "clandestine_port_value should have been > 1024, but was {}",
            clandestine_port_value
        );
        assert!(
            clandestine_port_value <= HIGHEST_RANDOM_CLANDESTINE_PORT,
            "clandestine_port_value should have been < 10000, but was {}",
            clandestine_port_value
        );
    }

    #[test]
    fn initialize_config_with_seed() {
        let home_dir =
            ensure_node_home_directory_exists("db_initializer", "initialize_config_with_seed");

        DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let mut stmt = conn
            .prepare("select name, value from config where name=?")
            .unwrap();
        let mut config_contents = stmt
            .query_map(&["seed"], |row| Ok((row.get(0), row.get(1))))
            .unwrap();

        let (name, value) = config_contents.next().unwrap().unwrap()
            as (Result<String, Error>, Result<String, Error>);
        assert_eq!(Ok(String::from("seed")), name);
        assert_eq!(
            Err(Error::InvalidColumnType(1, String::from("value"), Null)),
            value
        );
        assert!(config_contents.next().is_none());
    }

    #[test]
    fn nonexistent_directory_is_created_when_possible() {
        let data_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "nonexistent_directory_is_created_when_possible",
        );

        DbInitializerReal::create_data_directory_if_necessary(&data_dir);

        // If .unwrap() succeeds, test passes!(If not, it gives a better failure message than .is_ok())
        fs::read_dir(data_dir).unwrap();
    }

    #[test]
    fn directory_is_unmolested_if_present() {
        let data_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "directory_is_unmolested_if_present",
        );
        {
            let mut file = File::create(data_dir.join("booga.txt")).unwrap();
            file.write_all(b"unmolested").unwrap();
        }

        DbInitializerReal::create_data_directory_if_necessary(&data_dir);

        let mut file = File::open(data_dir.join("booga.txt")).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(String::from("unmolested"), contents);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic(expected = "Cannot create specified data directory at ")]
    fn linux_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[should_panic(expected = "Cannot create specified data directory at ")]
    fn macos_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic(expected = "Cannot create specified data directory at ")]
    fn windows_panic_if_directory_is_nonexistent_and_cant_be_created() {
        let base_path = PathBuf::from("M:\\nonexistent");
        panic_if_directory_is_nonexistent_and_cant_be_created(&base_path);
    }

    fn panic_if_directory_is_nonexistent_and_cant_be_created(base_path: &PathBuf) {
        DbInitializerReal::create_data_directory_if_necessary(&base_path.join("home"));
    }

    #[cfg(not(target_os = "windows"))]
    fn create_read_only_directory() -> PathBuf {
        let parent_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "panic_if_directory_is_nonexistent_and_cant_be_created",
        );
        let data_dir = parent_dir.join("uncreatable");
        match fs::metadata(&parent_dir) {
            Err(_) => (),
            Ok(metadata) => {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                fs::set_permissions(&parent_dir, permissions).unwrap();
            }
        }
        let mut permissions = fs::metadata(&parent_dir).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&parent_dir, permissions).unwrap();
        data_dir
    }
}
