// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::utils::{DaoFactoryReal, VigilantRusqliteFlatten};
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use lazy_static::lazy_static;
use rusqlite::{Error, ErrorCode, ToSql};
use std::collections::HashSet;
use std::sync::RwLock;

lazy_static! {
    pub static ref BAN_CACHE: BannedCache = BannedCache::default();
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
            .insert(wallet.as_address_wallet());
    }

    pub fn remove(&self, wallet: &Wallet) {
        self.cache
            .write()
            .expect("Failed to remove ban from cache")
            .remove(&wallet.as_address_wallet());
    }

    pub fn is_banned(&self, wallet: &Wallet) -> bool {
        self.cache
            .read()
            .expect("Failed to read from ban cache")
            .contains(&wallet.as_address_wallet())
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.cache.write().expect("Failed to clear cache").clear()
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
        stmt.query_map([], |row| row.get::<usize, Wallet>(0))
            .expect("Failed to query banned table")
            .map(|p| p.expect("query_map magically returned an Err"))
            .for_each(|wallet| BAN_CACHE.insert(wallet));
    }
}

pub trait BannedDao: Send {
    fn ban_list(&self) -> Vec<Wallet>;
    fn ban(&self, wallet: &Wallet);
    fn unban(&self, wallet: &Wallet);
}

pub trait BannedDaoFactory {
    fn make(&self) -> Box<dyn BannedDao>;
}

impl BannedDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn BannedDao> {
        Box::new(BannedDaoReal::new(self.make_connection()))
    }
}

pub struct BannedDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl BannedDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> Self {
        Self { conn }
    }
}

impl BannedDao for BannedDaoReal {
    fn ban_list(&self) -> Vec<Wallet> {
        let mut stmt = self
            .conn
            .prepare("select wallet_address from banned")
            .expect("Failed to prepare a statement");
        stmt.query_map([], |row| row.get(0))
            .expect("Couldn't retrieve delinquency-ban list: database corrupt")
            .vigilant_flatten()
            .collect()
    }

    fn ban(&self, wallet: &Wallet) {
        if BAN_CACHE.is_banned(wallet) {
            return;
        }

        let mut stmt = self
            .conn
            .prepare("insert into banned (wallet_address) values (?)")
            .expect("Failed to prepare a statement");
        let params: &[&dyn ToSql] = &[&wallet];
        match stmt.execute(params) {
            Ok(_) => BAN_CACHE.insert(wallet.clone()),
            Err(e) => match e {
                Error::SqliteFailure(e, _) if e.code == ErrorCode::ConstraintViolation => {
                    BAN_CACHE.insert(wallet.clone())
                }
                _ => panic!(
                    "Could not initiate delinquency ban for {} because of database corruption: {}",
                    wallet, e
                ),
            },
        }
    }

    fn unban(&self, wallet: &Wallet) {
        if !BAN_CACHE.is_banned(wallet) {
            return;
        }

        let mut stmt = self
            .conn
            .prepare("delete from banned where wallet_address = ?")
            .expect("Failed to prepare a statement");
        let params: &[&dyn ToSql] = &[&wallet];
        match stmt.execute(params) {
            Ok(_) => BAN_CACHE.remove(wallet),
            Err(e) => panic!(
                "Could not terminate delinquency ban for {} because of database corruption: {}",
                wallet, e
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::DbInitializationConfig;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
    };

    #[test]
    fn banned_dao_can_ban_a_wallet_address() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "banned_dao_can_ban_a_wallet_address",
        );
        let db_initializer = DbInitializerReal::default();
        let subject = {
            let conn = db_initializer
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
            BannedDaoReal::new(conn)
        };

        subject.ban(&make_wallet("donalddrumph"));

        let conn = db_initializer
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let mut stmt = conn.prepare("select wallet_address from banned").unwrap();
        let mut banned_addresses = stmt.query([]).unwrap();
        assert_eq!(
            "0x0000000000000000646f6e616c646472756d7068",
            banned_addresses
                .next()
                .unwrap()
                .unwrap()
                .get_unwrap::<usize, String>(0)
        );
    }

    #[test]
    fn ban_is_idempotent() {
        let home_dir = ensure_node_home_directory_does_not_exist("banned_dao", "ban_is_idempotent");
        let db_initializer = DbInitializerReal::default();
        let subject = {
            let conn = db_initializer
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
            BannedDaoReal::new(conn)
        };

        subject.ban(&make_wallet("no_duplicate_wallets"));
        subject.ban(&make_wallet("no_duplicate_wallets"));

        let ban_list = subject.ban_list();
        assert_eq!(vec![make_wallet("no_duplicate_wallets")], ban_list);
    }

    #[test]
    fn ban_error_when_table_doesnt_exist() {
        let home_dir =
            ensure_node_home_directory_exists("banned_dao", "ban_error_when_table_doesnt_exist");
        let db_initializer = DbInitializerReal::default();
        let subject = {
            let conn = db_initializer
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
            BannedDaoReal::new(conn)
        };

        subject.ban(&make_wallet("forgot_to_init"));
    }

    #[test]
    fn banned_dao_can_unban_a_wallet_address() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "banned_dao_can_unban_a_wallet_address",
        );
        let db_initializer = DbInitializerReal::default();

        let conn = db_initializer
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let wallet = &make_wallet("booga");
        conn.prepare("insert into banned (wallet_address) values (?)")
            .unwrap()
            .execute(&[&wallet])
            .unwrap();
        BAN_CACHE.insert(wallet.clone());
        let subject = BannedDaoReal::new(conn);

        subject.unban(wallet);

        let conn = db_initializer
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let mut stmt = conn
            .prepare("select wallet_address from banned where wallet_address = ?")
            .unwrap();
        let params: &[&dyn ToSql] = &[&"booga"];
        let mut results = stmt.query(params).unwrap();
        assert!(results.next().unwrap().is_none());
    }

    #[test]
    fn unban_is_okay_for_non_banned() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "unban_is_okay_for_non_banned");
        let db_initializer = DbInitializerReal::default();

        let conn = db_initializer
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = BannedDaoReal::new(conn);

        subject.unban(&make_wallet("hey_im_not_banned"));

        // No panic: test passes
    }

    #[test]
    fn is_banned_returns_true_for_banned() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "is_banned_returns_true_for_banned",
        );
        let db_initializer = DbInitializerReal::default();

        let conn = db_initializer
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        conn.prepare("insert into banned (wallet_address) values ('0x000000000000000000495f414d5f42414e4e4544')")
            .unwrap()
            .execute([])
            .unwrap();
        BannedCacheLoaderReal {}.load(conn);

        let result = BAN_CACHE.is_banned(&make_wallet("I_AM_BANNED"));

        assert!(result);
    }

    #[test]
    fn is_banned_returns_false_for_nonbanned() {
        let result = BAN_CACHE.is_banned(&make_wallet("I_AM_BANNED"));

        assert_eq!(false, result);
    }

    #[test]
    fn ban_inserts_into_ban_cache() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "ban_inserts_into_ban_cache");
        let db_initializer = DbInitializerReal::default();

        let conn = db_initializer
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = BannedDaoReal::new(conn);

        let ban_me_baby = make_wallet("BAN_ME_BABY");
        subject.ban(&ban_me_baby.clone());

        assert!(BAN_CACHE.is_banned(&ban_me_baby))
    }

    #[test]
    fn unban_removes_from_ban_cache() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "unban_removes_from_ban_cache");
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let unban_me_baby = make_wallet("UNBAN_ME_BABY");
        conn.prepare("insert into banned (wallet_address) values ('UNBAN_ME_BABY')")
            .unwrap()
            .execute([])
            .unwrap();
        BAN_CACHE.insert(unban_me_baby.clone());

        let subject = BannedDaoReal::new(conn);
        subject.unban(&unban_me_baby);

        assert!(!BAN_CACHE.is_banned(&unban_me_baby));
    }

    #[test]
    fn insert_adds_a_wallet_to_the_cache() {
        let now_banned_wallet = make_paying_wallet(b"NOW_BANNED_WALLET");
        let now_banned_address_wallet = Wallet::from(now_banned_wallet.address());

        BAN_CACHE.insert(now_banned_wallet.clone());

        assert!(BAN_CACHE.is_banned(&now_banned_wallet));
        assert!(BAN_CACHE.is_banned(&now_banned_address_wallet));
    }

    #[test]
    fn remove_removes_a_wallet_from_the_cache() {
        let already_banned_wallet = make_paying_wallet(b"ALREADY_BANNED_YO");
        let already_banned_address_wallet = Wallet::from(already_banned_wallet.address());
        BAN_CACHE.insert(already_banned_wallet.clone());

        BAN_CACHE.remove(&already_banned_wallet);

        assert!(!BAN_CACHE.is_banned(&already_banned_wallet));
        assert!(!BAN_CACHE.is_banned(&already_banned_address_wallet));
    }
}
