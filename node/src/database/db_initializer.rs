// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
use crate::database::db_migrations::{DbMigrator, DbMigratorReal, ExternalMigrationParameters};
use crate::db_config::secure_config_layer::EXAMPLE_ENCRYPTED;
use crate::sub_lib::logger::Logger;
use masq_lib::blockchains::chains::Chain;
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
pub const CURRENT_SCHEMA_VERSION: usize = 2;

#[derive(Debug, PartialEq)]
pub enum InitializationError {
    Nonexistent,
    UndetectableVersion(String),
    SqliteError(rusqlite::Error),
    DbMigrationError(String),
}

pub trait DbInitializer {
    fn initialize(
        &self,
        path: &Path,
        chain: Chain,
        create_if_necessary: bool,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError>;

    fn initialize_to_version(
        &self,
        path: &Path,
        chain: Chain,
        target_version: usize,
        create_if_necessary: bool,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError>;
}

pub struct DbInitializerReal {
    logger: Logger,
}

impl Default for DbInitializerReal {
    fn default() -> Self {
        Self {
            logger: Logger::new("DbInitializer"),
        }
    }
}

impl DbInitializer for DbInitializerReal {
    fn initialize(
        &self,
        path: &Path,
        chain: Chain,
        create_if_necessary: bool,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        self.initialize_to_version(path, chain, CURRENT_SCHEMA_VERSION, create_if_necessary)
    }

    fn initialize_to_version(
        &self,
        path: &Path,
        chain: Chain,
        target_version: usize,
        create_if_necessary: bool,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        let is_creation_necessary = Self::is_creation_necessary(path);
        if !create_if_necessary && is_creation_necessary {
            return Err(InitializationError::Nonexistent);
        }
        Self::create_data_directory_if_necessary(path);
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE;
        let database_file_path = &path.join(DATABASE_FILE);
        match Connection::open_with_flags(database_file_path, flags) {
            Ok(conn) => {
                eprintln!("Opened existing database at {:?}", database_file_path);
                let config = self.extract_configurations(&conn);
                let external_parameters = ExternalMigrationParameters::new(chain);
                let migrator = Box::new(DbMigratorReal::new(external_parameters));
                self.update_if_required_and_get_connection(
                    conn,
                    config.get("schema_version"),
                    target_version,
                    database_file_path,
                    flags,
                    migrator,
                )
            }
            Err(_) => {
                let mut flags = OpenFlags::empty();
                flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
                flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
                match Connection::open_with_flags(database_file_path, flags) {
                    Ok(conn) => {
                        eprintln!("Created new database at {:?}", database_file_path);
                        self.create_database_tables(&conn, chain);
                        Ok(Box::new(ConnectionWrapperReal::new(conn)))
                    }
                    Err(e) => Err(InitializationError::SqliteError(e)),
                }
            }
        }
    }
}

impl DbInitializerReal {
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

    fn create_database_tables(&self, conn: &Connection, chain: Chain) {
        self.create_config_table(conn);
        self.initialize_config(conn, chain);
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

    fn initialize_config(&self, conn: &Connection, chain: Chain) {
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
            "mapping_protocol",
            None,
            false,
            "protocol for port mapping on the router",
        );
        Self::set_config_value(
            conn,
            "schema_version",
            Some(&CURRENT_SCHEMA_VERSION.to_string()),
            false,
            "database version",
        );
        Self::set_config_value(
            conn,
            "chain_name",
            Some(chain.rec().literal_identifier),
            false,
            "the chain the database is created for",
        );
        Self::set_config_value(conn, "seed", None, true, "mnemonic seed");
        Self::set_config_value(
            conn,
            "start_block",
            Some(&chain.rec().contract_creation_block.to_string()),
            false,
            format!("{} start block", chain.rec().literal_identifier).as_str(),
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

    fn update_if_required_and_get_connection(
        &self,
        conn: Connection,
        version_found: Option<&Option<String>>,
        target_version: usize,
        db_file_path: &Path,
        opening_flags: OpenFlags,
        migrator: Box<dyn DbMigrator>,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        match version_found {
            None => Err(InitializationError::UndetectableVersion(format!(
                "Need {}, found nothing",
                CURRENT_SCHEMA_VERSION
            ))),
            Some(None) => Err(InitializationError::UndetectableVersion(format!(
                "Need {}, found nothing",
                CURRENT_SCHEMA_VERSION
            ))),
            Some(Some(v_from_db)) => {
                let v_from_db = Self::validate_schema_version(v_from_db);
                if v_from_db == CURRENT_SCHEMA_VERSION {
                    Ok(Box::new(ConnectionWrapperReal::new(conn)))
                } else {
                    warning!(
                        self.logger,
                        "Database is incompatible and its updating is necessary"
                    );
                    let wrapped_connection = ConnectionWrapperReal::new(conn);
                    match migrator.migrate_database(
                        v_from_db,
                        target_version,
                        Box::new(wrapped_connection),
                    ) {
                        Ok(_) => {
                            let wrapped_conn = self.double_check_the_result_of_db_migration(
                                db_file_path,
                                opening_flags,
                                target_version,
                            );
                            Ok(wrapped_conn)
                        }
                        Err(e) => Err(InitializationError::DbMigrationError(e)),
                    }
                }
            }
        }
    }

    fn double_check_the_result_of_db_migration(
        &self,
        db_file_path: &Path,
        opening_flags: OpenFlags,
        target_version: usize,
    ) -> Box<dyn ConnectionWrapper> {
        let conn = Connection::open_with_flags(db_file_path, opening_flags)
            .unwrap_or_else(|e| panic!("The database undoubtedly exists, but: {}", e));
        let config_table_content = self.extract_configurations(&conn);
        let schema_version_entry = config_table_content.get("schema_version");
        let found_schema = Self::validate_schema_version(
            schema_version_entry
                .expect("Db migration failed; cannot find a row with the schema version")
                .as_ref()
                .expect("Db migration failed; the value for the schema version is missing"),
        );
        if found_schema.eq(&target_version) {
            Box::new(ConnectionWrapperReal::new(conn))
        } else {
            panic!("DB migration failed; the resulting records are still incorrect")
        }
    }

    fn validate_schema_version(obtained_s_v: &str) -> usize {
        obtained_s_v.parse::<usize>().unwrap_or_else(|_| {
            panic!(
                "Database version should be purely numeric, but was: {}",
                obtained_s_v
            )
        })
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
    chain: Chain,
    create_if_necessary: bool,
) -> Box<dyn ConnectionWrapper> {
    db_initializer
        .initialize(path, chain, create_if_necessary)
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
    use masq_lib::blockchains::chains::Chain;
    use rusqlite::Transaction;
    use rusqlite::{Error, Statement};
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    pub struct ConnectionWrapperMock<'b, 'a: 'b> {
        prepare_params: Arc<Mutex<Vec<String>>>,
        prepare_results: RefCell<Vec<Result<Statement<'a>, Error>>>,
        transaction_results: RefCell<Vec<Result<Transaction<'b>, Error>>>,
    }

    unsafe impl<'a: 'b, 'b> Send for ConnectionWrapperMock<'a, 'b> {}

    impl<'a: 'b, 'b> ConnectionWrapperMock<'a, 'b> {
        pub fn prepare_result(self, result: Result<Statement<'a>, Error>) -> Self {
            self.prepare_results.borrow_mut().push(result);
            self
        }

        pub fn transaction_result(self, result: Result<Transaction<'b>, Error>) -> Self {
            self.transaction_results.borrow_mut().push(result);
            self
        }
    }

    impl<'a: 'b, 'b> ConnectionWrapper for ConnectionWrapperMock<'a, 'b> {
        fn prepare(&self, query: &str) -> Result<Statement, Error> {
            self.prepare_params
                .lock()
                .unwrap()
                .push(String::from(query));
            self.prepare_results.borrow_mut().remove(0)
        }

        fn transaction<'_a: '_b, '_b>(&'_a mut self) -> Result<Transaction<'_b>, Error> {
            self.transaction_results.borrow_mut().remove(0)
        }
    }

    #[derive(Default)]
    pub struct DbInitializerMock {
        pub initialize_params: Arc<Mutex<Vec<(PathBuf, Chain, bool)>>>,
        pub initialize_results:
            RefCell<Vec<Result<Box<dyn ConnectionWrapper>, InitializationError>>>,
    }

    impl DbInitializer for DbInitializerMock {
        fn initialize(
            &self,
            path: &Path,
            chain: Chain,
            create_if_necessary: bool,
        ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
            self.initialize_params.lock().unwrap().push((
                path.to_path_buf(),
                chain,
                create_if_necessary,
            ));
            self.initialize_results.borrow_mut().remove(0)
        }

        #[allow(unused_variables)]
        fn initialize_to_version(
            &self,
            path: &Path,
            chain: Chain,
            target_version: usize,
            create_if_necessary: bool,
        ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
            intentionally_blank!()
            /*all existing test calls only initialize() in the mocked version,
            but we need to call initialize_to_version() for the real object
            in order to carry out some important tests too*/
        }
    }

    impl DbInitializerMock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn initialize_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<(PathBuf, Chain, bool)>>>,
        ) -> DbInitializerMock {
            self.initialize_params = parameters;
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
    use crate::test_utils::database_utils::{
        revive_tables_of_the_version_0_and_return_the_connection_to_the_db, DbMigratorMock,
    };
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use itertools::Itertools;
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
        TEST_DEFAULT_CHAIN,
    };
    use rusqlite::types::Type::Null;
    use rusqlite::{Error, OpenFlags};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::ops::Not;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[test]
    fn db_initialize_does_not_create_if_directed_not_to_and_directory_does_not_exist() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "db_initialize_does_not_create_if_directed_not_to_and_directory_does_not_exist",
        );
        let subject = DbInitializerReal::default();

        let result = subject.initialize(&home_dir, TEST_DEFAULT_CHAIN, false);

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
        let subject = DbInitializerReal::default();

        let result = subject.initialize(&home_dir, TEST_DEFAULT_CHAIN, false);

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
        let subject = DbInitializerReal::default();

        subject
            .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
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
        let subject = DbInitializerReal::default();

        subject
            .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
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
        let subject = DbInitializerReal::default();

        subject
            .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
            .unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let mut stmt = conn.prepare("select wallet_address from banned").unwrap();
        let mut banned_contents = stmt.query_map(NO_PARAMS, |_| Ok(42)).unwrap();
        assert!(banned_contents.next().is_none());
    }

    #[test]
    #[should_panic(expected = "The database undoubtedly exists, but: unable to open database file")]
    fn double_check_the_result_of_db_migration_panics_if_cannot_reestablish_the_connection_to_the_database(
    ) {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "double_check_the_result_of_db_migration_panics_if_cannot_reestablish_the_connection_to_the_database",
        );
        let target_version = 1;
        let subject = DbInitializerReal::default();

        let _ = subject.double_check_the_result_of_db_migration(
            &home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            target_version,
        );
    }

    #[test]
    #[should_panic(expected = "DB migration failed; the resulting records are still incorrect")]
    fn panics_because_the_data_does_not_correspond_to_target_version_after_an_allegedly_successful_update(
    ) {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "panics_because_the_data_does_not_correspond_to_target_version_after_an_allegedly_successful_update",
        );
        let db_file_path = home_dir.join(DATABASE_FILE);
        let _ = revive_tables_of_the_version_0_and_return_the_connection_to_the_db(&db_file_path);
        let target_version = 1;
        //schema_version equals to 0 but current schema version must be at least 1 and more

        let subject = DbInitializerReal::default();

        let _ = subject.double_check_the_result_of_db_migration(
            &home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            target_version,
        );
    }

    #[test]
    fn existing_database_with_correct_version_is_accepted_without_changes() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_version_is_accepted",
        );
        let subject = DbInitializerReal::default();
        {
            DbInitializerReal::default()
                .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
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
            .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
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

        verify(
            &mut config_vec,
            "chain_name",
            Some(TEST_DEFAULT_CHAIN.rec().literal_identifier),
        );
        let clandestine_port_str_opt = verify_name(&mut config_vec, "clandestine_port");
        let clandestine_port: u16 = clandestine_port_str_opt.unwrap().parse().unwrap();
        assert!(clandestine_port >= 1025);
        assert!(clandestine_port < 10000);
        verify(&mut config_vec, "consuming_wallet_derivation_path", None);
        verify(&mut config_vec, "consuming_wallet_public_key", None);
        verify(&mut config_vec, "earning_wallet_address", None);
        verify(&mut config_vec, EXAMPLE_ENCRYPTED, None);
        verify(&mut config_vec, "gas_price", Some(DEFAULT_GAS_PRICE));
        verify(&mut config_vec, "mapping_protocol", None);
        verify(&mut config_vec, "past_neighbors", None);
        verify(&mut config_vec, "preexisting", Some("yes")); // makes sure we just created this database
        verify(
            &mut config_vec,
            "schema_version",
            Some(&CURRENT_SCHEMA_VERSION.to_string()),
        );
        verify(&mut config_vec, "seed", None);
        verify(
            &mut config_vec,
            "start_block",
            Some(&format!(
                "{}",
                &TEST_DEFAULT_CHAIN.rec().contract_creation_block.to_string()
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
            DbInitializerReal::default()
                .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
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
        let subject = DbInitializerReal::default();

        let result = subject.initialize(&home_dir, TEST_DEFAULT_CHAIN, true);

        assert_eq!(
            result.err().unwrap(),
            InitializationError::UndetectableVersion(format!(
                "Need {}, found nothing",
                CURRENT_SCHEMA_VERSION
            )),
        );
    }

    #[test]
    #[should_panic(expected = "Database version should be purely numeric, but was: boooobles")]
    fn existing_database_with_junk_in_place_of_its_schema_version_is_caught() {
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_junk_in_place_of_its_schema_version_is_caught",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
                .unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
            conn.execute(
                "update config set value = 'boooobles' where name = 'schema_version'",
                NO_PARAMS,
            )
            .unwrap();
        }
        let subject = DbInitializerReal::default();

        let _ = subject.initialize(&home_dir, TEST_DEFAULT_CHAIN, true);
    }

    #[test]
    fn existing_database_with_the_wrong_version_comes_to_migrator_that_makes_it_gradually_migrate_to_upper_versions(
    ) {
        init_test_logging();
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "existing_database_with_the_wrong_version_comes_to_migrator_that_makes_it_gradually_migrate_to_upper_versions",
        );
        let updated_db_path_dir = &home_dir.join("updated");
        let from_scratch_db_path_dir = &home_dir.join("from_scratch");
        std::fs::create_dir(updated_db_path_dir).unwrap();
        std::fs::create_dir(from_scratch_db_path_dir).unwrap();
        {
            revive_tables_of_the_version_0_and_return_the_connection_to_the_db(
                &updated_db_path_dir.join(DATABASE_FILE),
            );
        }
        let subject = DbInitializerReal::default();

        let _ = subject
            .initialize(&updated_db_path_dir, TEST_DEFAULT_CHAIN, true)
            .unwrap();
        let _ = subject
            .initialize(&from_scratch_db_path_dir, TEST_DEFAULT_CHAIN, true)
            .unwrap();

        let conn_updated = Connection::open_with_flags(
            &updated_db_path_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let conn_from_scratch = Connection::open_with_flags(
            &from_scratch_db_path_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let extract_from_updated = subject.extract_configurations(&conn_updated);
        let extract_from_from_scratch = subject.extract_configurations(&conn_from_scratch);
        //please, write all rows with unpredictable values here
        let sieve = |updated_parameter: &String| updated_parameter != "clandestine_port";
        let zipped_iterators = extract_from_updated
            .iter()
            .sorted()
            .zip(extract_from_from_scratch.iter().sorted());
        //with regular values
        zipped_iterators
            .clone()
            .take_while(|((parameter_name, _), _)| sieve(parameter_name))
            .for_each(|(updated, from_scratch)| assert_eq!(updated, from_scratch));
        //with irregular values
        zipped_iterators
            .take_while(|((parameter_name, _), _)| sieve(parameter_name).not())
            .for_each(|(updated, from_scratch)| assert_eq!(updated.0, from_scratch.0));
        TestLogHandler::new().exists_log_containing(
            "WARN: DbInitializer: Database is incompatible and its updating is necessary",
        );
    }

    #[test]
    fn update_if_required_and_get_connection_starts_db_migration_and_hands_in_an_error_from_database_operations(
    ) {
        init_test_logging();
        let home_dir = ensure_node_home_directory_exists(
            "db_initializer",
            "update_if_required_and_get_connection_starts_db_migration_and_hands_in_an_error_from_database_operations",
        );
        let migrate_database_params_arc = Arc::new(Mutex::new(vec![]));
        let db_file_path = home_dir.join(DATABASE_FILE);
        let conn = Connection::open(&db_file_path).unwrap();
        let subject = DbInitializerReal::default();
        let target_version = 5; //not relevant
        let migrator = Box::new(DbMigratorMock::default().inject_logger()
            .migrate_database_params(&migrate_database_params_arc)
            .migrate_database_result(Err("Updating database from version 0 to 1 failed: Transaction couldn't be processed".to_string())));

        let result = subject.update_if_required_and_get_connection(
            conn,
            Some(&Some("0".to_string())),
            target_version,
            &db_file_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            migrator,
        );

        let error = match result {
            Ok(_) => panic!("expected Err got Ok"),
            Err(e) => e,
        };
        assert_eq!(
            error,
            InitializationError::DbMigrationError(
                "Updating database from version 0 to 1 failed: Transaction couldn't be processed"
                    .to_string()
            )
        );
        let mut migrate_database_params = migrate_database_params_arc.lock().unwrap();
        let (mismatched_schema, target_version, connection_wrapper) =
            migrate_database_params.remove(0);
        assert_eq!(mismatched_schema, 0);
        assert_eq!(target_version, 5);
        assert!(connection_wrapper
            .as_any()
            .downcast_ref::<ConnectionWrapperReal>()
            .is_some());
        TestLogHandler::new().exists_log_containing(
            "WARN: DbInitializer: Database is incompatible and its updating is necessary",
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

        DbInitializerReal::default()
            .initialize(&home_dir, TEST_DEFAULT_CHAIN, true)
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
        assert_eq!(name, Ok(String::from("seed")));
        assert_eq!(
            value,
            Err(Error::InvalidColumnType(1, String::from("value"), Null))
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
