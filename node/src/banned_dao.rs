// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use lazy_static::lazy_static;
use rusqlite::{Error, ErrorCode, ToSql, NO_PARAMS};
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

pub trait BannedDao {
    fn ban_list(&self) -> Vec<Wallet>;
    fn ban(&self, wallet_address: &Wallet);
    fn unban(&self, wallet_address: &Wallet);
}

pub struct BannedDaoReal {
    conn: Box<ConnectionWrapper>,
}

impl BannedDaoReal {
    pub fn new(conn: Box<ConnectionWrapper>) -> Self {
        Self { conn }
    }
}

impl BannedDao for BannedDaoReal {
    fn ban_list(&self) -> Vec<Wallet> {
        let mut stmt = self
            .conn
            .prepare("select wallet_address from banned")
            .expect("Failed to prepare a statement");
        stmt.query_map(NO_PARAMS, |row| {
            let wallet_address: String = row
                .get(0)
                .expect("Database is corrupt: BANNED table columns and/or types");
            Ok(Wallet::new(&wallet_address))
        })
        .expect("Couldn't retrieve delinquency-ban list: database corrupt")
        .into_iter()
        .flat_map(|v| v)
        .collect()
    }

    fn ban(&self, wallet_address: &Wallet) {
        if BAN_CACHE.is_banned(wallet_address) {
            return;
        }

        let mut stmt = self
            .conn
            .prepare("insert into banned (wallet_address) values (?)")
            .expect("Failed to prepare a statement");
        let params: &[&ToSql] = &[&wallet_address.address];
        match stmt.execute(params) {
            Ok(_) => BAN_CACHE.insert(wallet_address.clone()),
            Err(e) => match e {
                Error::SqliteFailure(e, _) if e.code == ErrorCode::ConstraintViolation => {
                    BAN_CACHE.insert(wallet_address.clone())
                }
                _ => panic!(format!(
                    "Could not initiate delinquency ban for {} because of database corruption: {}",
                    wallet_address, e
                )),
            },
        }
    }

    fn unban(&self, wallet_address: &Wallet) {
        if !BAN_CACHE.is_banned(wallet_address) {
            return;
        }

        let mut stmt = self
            .conn
            .prepare("delete from banned where wallet_address = ?")
            .expect("Failed to prepare a statement");
        let params: &[&ToSql] = &[&wallet_address.address];
        match stmt.execute(params) {
            Ok(_) => BAN_CACHE.remove(&wallet_address),
            Err(e) => panic!(format!(
                "Could not terminate delinquency ban for {} because of database corruption: {}",
                wallet_address, e
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::test_utils::test_utils::{
        ensure_node_home_directory_does_not_exist, ensure_node_home_directory_exists,
    };
    use rusqlite::NO_PARAMS;

    #[test]
    fn banned_dao_can_ban_a_wallet_address() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "banned_dao_can_ban_a_wallet_address",
        );
        let db_initializer = DbInitializerReal::new();
        let subject = {
            let conn = db_initializer.initialize(&home_dir).unwrap();
            BannedDaoReal::new(conn)
        };

        subject.ban(&Wallet::new("donalddrumph"));

        let conn = db_initializer.initialize(&home_dir).unwrap();
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
    fn ban_is_idempotent() {
        let home_dir = ensure_node_home_directory_does_not_exist("banned_dao", "ban_is_idempotent");
        let db_initializer = DbInitializerReal::new();
        let subject = {
            let conn = db_initializer.initialize(&home_dir).unwrap();
            BannedDaoReal::new(conn)
        };

        subject.ban(&Wallet::new("no_duplicate_wallets"));
        subject.ban(&Wallet::new("no_duplicate_wallets"));

        let ban_list = subject.ban_list();
        assert_eq!(vec![Wallet::new("no_duplicate_wallets")], ban_list);
    }

    #[test]
    fn ban_error_when_table_doesnt_exist() {
        let home_dir =
            ensure_node_home_directory_exists("banned_dao", "ban_error_when_table_doesnt_exist");
        let db_initializer = DbInitializerReal::new();
        let subject = {
            let conn = db_initializer.initialize(&home_dir).unwrap();
            BannedDaoReal::new(conn)
        };

        subject.ban(&Wallet::new("forgot_to_init"));
    }

    #[test]
    fn banned_dao_can_unban_a_wallet_address() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "banned_dao_can_unban_a_wallet_address",
        );
        let db_initializer = DbInitializerReal::new();

        let conn = db_initializer.initialize(&home_dir).unwrap();
        let wallet_address = &Wallet::new("booga");
        conn.prepare("insert into banned (wallet_address) values (?)")
            .unwrap()
            .execute(&[&wallet_address.address])
            .unwrap();
        BAN_CACHE
            .cache
            .write()
            .unwrap()
            .insert(wallet_address.clone());
        let subject = BannedDaoReal::new(conn);

        subject.unban(wallet_address);

        let conn = db_initializer.initialize(&home_dir).unwrap();
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
        let db_initializer = DbInitializerReal::new();

        let conn = db_initializer.initialize(&home_dir).unwrap();
        let subject = BannedDaoReal::new(conn);

        subject.unban(&Wallet::new("hey_im_not_banned"));

        // No panic: test passes
    }

    #[test]
    fn is_banned_returns_true_for_banned() {
        let home_dir = ensure_node_home_directory_does_not_exist(
            "banned_dao",
            "is_banned_returns_true_for_banned",
        );
        let db_initializer = DbInitializerReal::new();

        let conn = db_initializer.initialize(&home_dir).unwrap();
        conn.prepare("insert into banned (wallet_address) values ('I_AM_BANNED')")
            .unwrap()
            .execute(NO_PARAMS)
            .unwrap();
        BannedCacheLoaderReal {}.load(conn);

        let result = BAN_CACHE.is_banned(&Wallet::new("I_AM_BANNED"));

        assert!(result);
    }

    #[test]
    fn is_banned_returns_false_for_nonbanned() {
        let result = BAN_CACHE.is_banned(&Wallet::new("I_AM_BANNED"));

        assert_eq!(false, result);
    }

    #[test]
    fn ban_inserts_into_ban_cache() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "ban_inserts_into_ban_cache");
        let db_initializer = DbInitializerReal::new();

        let conn = db_initializer.initialize(&home_dir).unwrap();
        let subject = BannedDaoReal::new(conn);

        let ban_me_baby = Wallet::new("BAN_ME_BABY");
        subject.ban(&ban_me_baby.clone());

        assert!(BAN_CACHE.cache.read().unwrap().contains(&ban_me_baby))
    }

    #[test]
    fn unban_removes_from_ban_cache() {
        let home_dir =
            ensure_node_home_directory_does_not_exist("banned_dao", "unban_removes_from_ban_cache");
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer.initialize(&home_dir).unwrap();
        let unban_me_baby = Wallet::new("UNBAN_ME_BABY");
        conn.prepare("insert into banned (wallet_address) values ('UNBAN_ME_BABY')")
            .unwrap()
            .execute(NO_PARAMS)
            .unwrap();
        BAN_CACHE
            .cache
            .write()
            .unwrap()
            .insert(unban_me_baby.clone());

        let subject = BannedDaoReal::new(conn);
        subject.unban(&unban_me_baby);

        assert!(!BAN_CACHE.cache.read().unwrap().contains(&unban_me_baby));
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
