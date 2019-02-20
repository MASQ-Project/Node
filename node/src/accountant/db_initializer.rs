// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::payable_dao::PayableDao;
use super::payable_dao::PayableDaoReal;
use super::receivable_dao::ReceivableDao;
use super::receivable_dao::ReceivableDaoReal;
use rusqlite::Connection;
use rusqlite::OpenFlags;
use rusqlite::NO_PARAMS;
use std::collections::HashMap;
use std::path::PathBuf;

pub const DATABASE_FILE: &str = "node_data.sqlite";
pub const CURRENT_SCHEMA_VERSION: &str = "0.0.1";

#[derive(Debug, PartialEq)]
pub enum InitializationError {
    IncompatibleVersion,
}

#[derive(Debug)]
pub struct Daos {
    pub payable: Box<PayableDao>,
    pub receivable: Box<ReceivableDao>,
}

pub trait DbInitializer {
    fn initialize(&self, path: &PathBuf) -> Result<Daos, InitializationError>;
}

pub struct DbInitializerReal {}

impl DbInitializer for DbInitializerReal {
    fn initialize(&self, path: &PathBuf) -> Result<Daos, InitializationError> {
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let database_file_path = &path.join(DATABASE_FILE);
        let conn = match Connection::open_with_flags(database_file_path, flags) {
            Ok(conn) => {
                let config = self.extract_configurations(&conn);
                match self.check_version(config.get(&String::from("schema_version"))) {
                    Ok(_) => conn,
                    Err(e) => return Err(e),
                }
            }
            Err(_) => {
                let mut flags = OpenFlags::empty();
                flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
                flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
                let conn = Connection::open_with_flags(database_file_path, flags).expect(
                    format!("Database can't be created at {:?}", database_file_path).as_str(),
                );
                match self.create_database_tables(&conn) {
                    Ok(()) => conn,
                    Err(e) => return Err(e),
                }
            }
        };
        let payable = PayableDaoReal::new(conn);
        let conn = Connection::open_with_flags(database_file_path, flags)
            .expect("Database suddenly disappeared");
        let receivable = ReceivableDaoReal::new(conn);
        Ok(Daos {
            payable: Box::new(payable),
            receivable: Box::new(receivable),
        })
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
            .query_map(NO_PARAMS, |row| (row.get(0), row.get(1)))
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
mod tests {
    use super::super::local_test_utils::ensure_node_home_directory_exists;
    use super::*;
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
            .query_map(NO_PARAMS, |row| (row.get(0), row.get(1)))
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
        let mut payable_contents = stmt.query_map(NO_PARAMS, |_| 42).unwrap();
        assert!(payable_contents.next().is_none());
        let mut stmt = conn
            .prepare("select wallet_address, balance, last_received_timestamp from receivable")
            .unwrap();
        let mut receivable_contents = stmt.query_map(NO_PARAMS, |_| 42).unwrap();
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
            .query_map(NO_PARAMS, |row| (row.get(0), row.get(1)))
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
