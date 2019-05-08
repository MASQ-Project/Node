// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::persistent_configuration::{
    HIGHEST_RANDOM_CLANDESTINE_PORT, LOWEST_USABLE_INSECURE_PORT,
};
use rand::rngs::SmallRng;
use rand::FromEntropy;
use rand::Rng;
use rusqlite::NO_PARAMS;
use rusqlite::{Connection, Statement};
use rusqlite::{Error, OpenFlags};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use tokio::net::TcpListener;

pub const DATABASE_FILE: &str = "node_data.sqlite";
pub const CURRENT_SCHEMA_VERSION: &str = "0.0.2";

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
    SqliteError(rusqlite::Error),
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
        Self::create_data_directory_if_necessary(path);
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
                    Err(e) => Err(InitializationError::SqliteError(e)),
                }
            }
        }
    }
}

impl DbInitializerReal {
    pub fn new() -> DbInitializerReal {
        DbInitializerReal {}
    }

    fn create_data_directory_if_necessary(data_directory: &PathBuf) {
        match fs::read_dir(data_directory) {
            Ok(_) => (),
            Err(_) => fs::create_dir_all(data_directory).expect(
                format!(
                    "Cannot create specified data directory at {:?}",
                    data_directory
                )
                .as_str(),
            ),
        }
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
        .expect("Can't preload config table with database version");
        conn.execute(
            format!(
                "insert into config (name, value) values ('clandestine_port', '{}')",
                Self::choose_clandestine_port().to_string(),
            )
            .as_str(),
            NO_PARAMS,
        )
        .expect("Can't preload config table with clandestine port");
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
    use crate::test_utils::test_utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
    };
    use rusqlite::OpenFlags;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::net::TcpListener;

    #[test]
    fn nonexistent_database_is_created_in_nonexistent_directory() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "accountant",
            "nonexistent_database_is_created",
        );
        let subject = DbInitializerReal::new();

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
        let (clandestine_port_name, clandestine_port_value_str): (String, String) =
            config_contents.next().unwrap().unwrap();
        let clandestine_port_value = clandestine_port_value_str.parse::<u16>().unwrap();
        assert_eq!("clandestine_port".to_string(), clandestine_port_name);
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
        assert_eq!(
            config_contents.next().unwrap().unwrap(),
            (
                String::from("schema_version"),
                String::from(CURRENT_SCHEMA_VERSION)
            )
        );
        assert!(config_contents.next().is_none());
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
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "existing_database_with_version_is_accepted",
        );
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
        let (name, _) = config_contents.next().unwrap().unwrap();
        assert_eq!("clandestine_port", name);
        assert_eq!(
            config_contents.next().unwrap().unwrap(),
            (String::from("preexisting"), String::from("yes"))
        );
        assert_eq!(
            config_contents.next().unwrap().unwrap(),
            (
                String::from("schema_version"),
                String::from(CURRENT_SCHEMA_VERSION)
            )
        );
        assert!(config_contents.next().is_none());
    }

    #[test]
    fn existing_database_with_no_version_is_rejected() {
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "existing_database_with_no_version_is_rejected",
        );
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
            "accountant",
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

    #[test]
    fn choose_clandestine_port_chooses_different_unused_ports_each_time() {
        let _listeners = (0..10)
            .into_iter()
            .map(|_| {
                let port = DbInitializerReal::choose_clandestine_port();
                TcpListener::bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), port)))
                    .expect(&format!("Port {} was not free", port))
            })
            .collect::<Vec<TcpListener>>();
    }

    #[test]
    fn nonexistent_directory_is_created_when_possible() {
        let data_dir = ensure_node_home_directory_does_not_exist(
            "db_initializer",
            "nonexistent_directory_is_created_when_possible",
        );

        DbInitializerReal::create_data_directory_if_necessary(&data_dir);

        // If .unwrap() succeeds, test passes! (If not, it gives a better failure message than .is_ok())
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
            file.write(b"unmolested").unwrap();
        }

        DbInitializerReal::create_data_directory_if_necessary(&data_dir);

        let mut file = File::open(data_dir.join("booga.txt")).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, String::from("unmolested"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic(
        expected = "Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }"
    )]
    fn linux_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[should_panic(
        expected = "Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }"
    )]
    fn macos_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic(
        expected = "Custom { kind: Other, error: StringError(\"failed to create whole tree\") }"
    )]
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
