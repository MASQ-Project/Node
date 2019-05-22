// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::banned_dao::BannedDaoError::BanError;
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use lazy_static::lazy_static;
use rusqlite::{Error, ErrorCode, ToSql, NO_PARAMS};
use std::collections::HashSet;
use std::sync::RwLock;

lazy_static! {
    static ref BAN_CACHE: BannedCache = BannedCache::default();
}

#[derive(Default)]
pub struct BannedCache {
    cache: RwLock<HashSet<Wallet>>,
}

impl BannedCache {
    pub fn insert(&self, wallet: Wallet) {
        self.cache
            .write()
            .expect("Failed to insert ban into cache")
            .insert(wallet);
    }

    pub fn remove(&self, wallet: &Wallet) {
        self.cache
            .write()
            .expect("Failed to remove ban from cache")
            .remove(wallet);
    }

    pub fn is_banned(&self, wallet: &Wallet) -> bool {
        self.cache
            .read()
            .expect("Failed to read from ban cache")
            .contains(wallet)
    }
}

pub trait BannedCacheLoader {
    fn load(&self, conn: Box<dyn ConnectionWrapper>);
}

pub struct BannedCacheLoaderReal {}

impl BannedCacheLoader for BannedCacheLoaderReal {
    fn load(&self, conn: Box<dyn ConnectionWrapper>) {
        let mut stmt = conn
            .prepare("select wallet_address from banned")
            .expect("Failed to prepare statement");
        stmt.query_map(NO_PARAMS, |row| {
            Ok(Wallet::new(
                &row.get::<usize, String>(0)
                    .expect("Failed to extract wallet_address from Row"),
            ))
        })
        .expect("Failed to query banned table")
        .map(|p| p.expect("query_map magically returned an Err"))
        .for_each(|wallet| BAN_CACHE.insert(wallet));
    }
}

#[derive(Debug, PartialEq)]
pub enum BannedDaoError {
    BanError(Error),
}

#[allow(dead_code)]
pub trait BannedDao {
    fn is_banned(&self, wallet_address: &Wallet) -> bool;
    fn ban(&self, wallet_address: &Wallet) -> Result<(), BannedDaoError>;
    fn unban(&self, wallet_address: &Wallet) -> Result<(), BannedDaoError>;
}

#[allow(dead_code)]
pub struct BannedDaoReal {
    conn: Box<ConnectionWrapper>,
}

#[allow(dead_code)]
impl BannedDaoReal {
    pub fn new(conn: Box<ConnectionWrapper>) -> Self {
        Self { conn }
    }
}

impl BannedDao for BannedDaoReal {
    fn is_banned(&self, wallet_address: &Wallet) -> bool {
        BAN_CACHE.is_banned(wallet_address)
    }

    fn ban(&self, wallet_address: &Wallet) -> Result<(), BannedDaoError> {
        if self.is_banned(wallet_address) {
            return Ok(());
        }

        let mut stmt = self
            .conn
            .prepare("insert into banned (wallet_address) values (?)")
            .expect("Failed to prepare a statement");
        let params: &[&ToSql] = &[&wallet_address.address];
        match stmt.execute(params) {
            Ok(_) => {
                BAN_CACHE.insert(wallet_address.clone());
                Ok(())
            }
            Err(e) => match e {
                Error::SqliteFailure(e, _) if e.code == ErrorCode::ConstraintViolation => {
                    BAN_CACHE.insert(wallet_address.clone());
                    Ok(())
                }
                _ => Err(BanError(e)),
            },
        }
    }

    fn unban(&self, wallet_address: &Wallet) -> Result<(), BannedDaoError> {
        if !self.is_banned(wallet_address) {
            return Ok(());
        }

        let mut stmt = self
            .conn
            .prepare("delete from banned where wallet_address = ?")
            .expect("Failed to prepare a statement");
        let params: &[&ToSql] = &[&wallet_address.address];
        match stmt.execute(params) {
            Ok(_) => {
                BAN_CACHE.remove(&wallet_address);
                Ok(())
            }
            Err(e) => Err(BanError(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::{
        ConnectionWrapperReal, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::test_utils::test_utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
    };
    use rusqlite::{Connection, OpenFlags, NO_PARAMS};

    #[test]
    fn banned_dao_can_ban_a_wallet_address() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "banned_dao_can_ban_a_wallet_address",
        );
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        subject.ban(&Wallet::new("donalddrumph")).unwrap();

        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let mut stmt = conn.prepare("select wallet_address from banned").unwrap();
        let mut banned_addresses = stmt.query(NO_PARAMS).unwrap();
        assert_eq!(
            "donalddrumph",
            banned_addresses
                .next()
                .unwrap()
                .unwrap()
                .get_unwrap::<usize, String>(0)
        );
    }

    #[test]
    fn ban_twice_results_in_ok() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "ban_twice_results_in_error");
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        subject.ban(&Wallet::new("no_duplicate_wallets")).unwrap();
        let result = subject.ban(&Wallet::new("no_duplicate_wallets"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn ban_error_when_table_doesnt_exist() {
        let home_dir =
            ensure_node_home_directory_exists("banned_dao", "ban_error_when_table_doesnt_exist");

        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        let result = subject.ban(&Wallet::new("forgot_to_init"));

        assert_eq!(
            Err(BanError(Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: ErrorCode::ReadOnly,
                    extended_code: 8
                },
                Some(String::from("attempt to write a readonly database"))
            ))),
            result
        );
    }

    #[test]
    fn banned_dao_can_unban_a_wallet_address() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "banned_dao_can_unban_a_wallet_address",
        );
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let wallet_address = &Wallet::new("booga");
        conn.execute(
            "insert into banned (wallet_address) values (?)",
            &[&wallet_address.address],
        )
        .unwrap();
        BAN_CACHE
            .cache
            .write()
            .unwrap()
            .insert(wallet_address.clone());

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        subject.unban(wallet_address).unwrap();

        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let mut stmt = conn
            .prepare("select wallet_address from banned where wallet_address = ?")
            .unwrap();
        let params: &[&ToSql] = &[&"booga"];
        let mut results = stmt.query(params).unwrap();
        assert!(results.next().unwrap().is_none());
    }

    #[test]
    fn unban_is_okay_for_non_banned() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "unban_is_okay_for_non_banned");
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        let result = subject.unban(&Wallet::new("hey_im_not_banned"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn is_banned_returns_true_for_banned() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "is_banned_returns_true_for_banned",
        );
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        conn.execute(
            "insert into banned (wallet_address) values ('I_AM_BANNED')",
            NO_PARAMS,
        )
        .unwrap();

        BannedCacheLoaderReal {}.load(Box::new(ConnectionWrapperReal::new(conn)));

        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        let result = subject.is_banned(&Wallet::new("I_AM_BANNED"));

        assert!(result);
    }

    #[test]
    fn is_banned_returns_false_for_nonbanned() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "is_banned_returns_false_for_nonbanned",
        );
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        let result = subject.is_banned(&Wallet::new("I_AM_BANNED"));

        assert_eq!(false, result);
    }

    #[test]
    fn ban_inserts_into_ban_cache() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "ban_inserts_into_ban_cache");
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));

        let ban_me_baby = Wallet::new("BAN_ME_BABY");
        subject.ban(&ban_me_baby.clone()).unwrap();

        assert!(BAN_CACHE.cache.read().unwrap().contains(&ban_me_baby))
    }

    #[test]
    fn unban_removes_from_ban_cache() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "unban_removes_from_ban_cache");
        let db_initalizer = DbInitializerReal::new();

        db_initalizer.initialize(&home_dir).unwrap();

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);

        let unban_me_baby = Wallet::new("UNBAN_ME_BABY");

        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        conn.execute(
            "insert into banned (wallet_address) values ('UNBAN_ME_BABY')",
            NO_PARAMS,
        )
        .unwrap();

        BAN_CACHE
            .cache
            .write()
            .unwrap()
            .insert(unban_me_baby.clone());

        let subject = BannedDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));
        subject.unban(&unban_me_baby).unwrap();

        assert!(!BAN_CACHE.cache.read().unwrap().contains(&unban_me_baby));
    }

    #[test]
    #[should_panic(expected = "Failed to prepare statement")]
    fn load_panics_when_database_does_not_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "banned_dao",
            "load_panics_when_database_does_not_exist",
        );

        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();

        BannedCacheLoaderReal {}.load(Box::new(ConnectionWrapperReal::new(conn)));
    }

    #[test]
    fn insert_adds_a_wallet_to_the_cache() {
        let now_banned_wallet = Wallet::new("NOW_BANNED_WALLET");

        BAN_CACHE.insert(now_banned_wallet.clone());

        assert!(BAN_CACHE.cache.read().unwrap().contains(&now_banned_wallet));
    }

    #[test]
    fn remove_removes_a_wallet_from_the_cache() {
        let already_banned_wallet = Wallet::new("ALREADY_BANNED_YO");

        BAN_CACHE
            .cache
            .write()
            .unwrap()
            .insert(already_banned_wallet.clone());

        BAN_CACHE.remove(&already_banned_wallet);

        assert!(!BAN_CACHE
            .cache
            .read()
            .unwrap()
            .contains(&already_banned_wallet));
    }
}
