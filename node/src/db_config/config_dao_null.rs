// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_initializer::{DbInitializerReal, ENCRYPTED_ROWS};
use crate::db_config::config_dao::{
    ConfigDao, ConfigDaoError, ConfigDaoRead, ConfigDaoReadWrite, ConfigDaoRecord, ConfigDaoWrite,
};
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::{
    DEFAULT_PAYABLE_SCAN_INTERVAL, DEFAULT_PAYMENT_CURVES, DEFAULT_PENDING_PAYMENT_SCAN_INTERVAL,
    DEFAULT_RATE_PACK, DEFAULT_RECEIVABLE_SCAN_INTERVAL, ETH_MAINNET_CONTRACT_CREATION_BLOCK,
};
use rusqlite::Transaction;
use std::collections::HashMap;

/*

This class exists because the Daemon uses the same configuration code that the Node uses, and
that configuration code requires access to the database...except that the Daemon isn't allowed
access to the database, so it's given this configuration DAO instead. This DAO provides plain-vanilla
default values when read, and claims to have successfully written values (which are actually
thrown away) when updated.

Theoretically, the Daemon could be given access to the real database, but there are a few problems
that would need to be overcome first.

1. The database must be created by a normal user, not by root--or at least once it's finished it
must _look_ as though it were created by a normal user. The Daemon must always run as root, and
may not give up its privilege. This is not an insurmountable problem, but it is a problem.

2. The database can't be located until the chain is known, because the chain is part of the
directory to the database. Every setup command has the potential to need access to the database,
but there's no easy way to ensure that the first setup command establishes the chain.

3. If the database needs to be migrated from its schema version to the Daemon's schema version,
and the migration involves secret fields, then the migration will need the database password.
Again, the password will be needed the moment the database is first connected, which will probably
be when the first setup command is given, and there's no easy way to ensure that the first setup
command establishes the password.

4. If two different processes have simultaneous write access to the same database, one process may
make changes that the other process doesn't know about.  This is another problem that is not
insurmountable, but it would need to be considered and coded around.

 */

pub struct ConfigDaoNull {
    data: HashMap<String, String>,
}

impl ConfigDao for ConfigDaoNull {
    fn start_transaction<'b, 'c: 'b>(
        &'c mut self,
    ) -> Result<Box<dyn ConfigDaoReadWrite + 'b>, ConfigDaoError> {
        Ok(Box::new(ConfigDaoNull::default()))
    }
}

impl ConfigDaoRead for ConfigDaoNull {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        let keys = self.data.keys().sorted();
        Ok(keys
            .map(|key| {
                ConfigDaoRecord::new(
                    key,
                    Some(self.data.get(key).expect("Value disappeared")),
                    false,
                )
            })
            .collect())
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        let is_encrypted = ENCRYPTED_ROWS.contains(&name);
        Ok(ConfigDaoRecord::new(
            name,
            self.data.get(name).map(|s| s.as_str()),
            is_encrypted,
        ))
    }
}

impl ConfigDaoWrite for ConfigDaoNull {
    fn set(&self, _name: &str, _value: Option<String>) -> Result<(), ConfigDaoError> {
        Ok(())
    }

    fn commit(&mut self) -> Result<(), ConfigDaoError> {
        Ok(())
    }

    fn extract(&mut self) -> Result<Transaction, ConfigDaoError> {
        intentionally_blank!()
    }
}

impl ConfigDaoReadWrite for ConfigDaoNull {}

impl Default for ConfigDaoNull {
    fn default() -> Self {
        let mut data = HashMap::new();
        data.insert(
            "chain_name".to_string(),
            Chain::default().rec().literal_identifier.to_string(),
        );
        data.insert(
            "clandestine_port".to_string(),
            DbInitializerReal::choose_clandestine_port().to_string(),
        );
        data.insert("gas_price".to_string(), "1".to_string());
        data.insert(
            "start_block".to_string(),
            ETH_MAINNET_CONTRACT_CREATION_BLOCK.to_string(),
        );
        data.insert(
            "balance_decreases_for_sec".to_string(),
            DEFAULT_PAYMENT_CURVES.balance_decreases_for_sec.to_string(),
        );
        data.insert(
            "balance_to_decrease_from_gwei".to_string(),
            DEFAULT_PAYMENT_CURVES
                .balance_to_decrease_from_gwei
                .to_string(),
        );
        data.insert(
            "exit_byte_rate".to_string(),
            DEFAULT_RATE_PACK.exit_byte_rate.to_string(),
        );
        data.insert(
            "exit_service_rate".to_string(),
            DEFAULT_RATE_PACK.exit_service_rate.to_string(),
        );
        data.insert(
            "payable_scan_interval".to_string(),
            DEFAULT_PAYABLE_SCAN_INTERVAL.to_string(),
        );
        data.insert(
            "payment_grace_before_ban_sec".to_string(),
            DEFAULT_PAYMENT_CURVES
                .payment_grace_before_ban_sec
                .to_string(),
        );
        data.insert(
            "payment_suggested_after_sec".to_string(),
            DEFAULT_PAYMENT_CURVES
                .payment_suggested_after_sec
                .to_string(),
        );
        data.insert(
            "pending_payment_scan_interval".to_string(),
            DEFAULT_PENDING_PAYMENT_SCAN_INTERVAL.to_string(),
        );
        data.insert(
            "permanent_debt_allowed_gwei".to_string(),
            DEFAULT_PAYMENT_CURVES
                .permanent_debt_allowed_gwei
                .to_string(),
        );
        data.insert(
            "receivable_scan_interval".to_string(),
            DEFAULT_RECEIVABLE_SCAN_INTERVAL.to_string(),
        );
        data.insert(
            "routing_byte_rate".to_string(),
            DEFAULT_RATE_PACK.routing_byte_rate.to_string(),
        );
        data.insert(
            "routing_service_rate".to_string(),
            DEFAULT_RATE_PACK.routing_service_rate.to_string(),
        );
        data.insert(
            "unban_when_balance_below_gwei".to_string(),
            DEFAULT_PAYMENT_CURVES
                .unban_when_balance_below_gwei
                .to_string(),
        );
        Self { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::DbInitializer;
    use crate::database::db_migrations::MigratorConfig;
    use crate::db_config::config_dao::ConfigDaoReal;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::{
        DEFAULT_PAYABLE_SCAN_INTERVAL, DEFAULT_PAYMENT_CURVES,
        DEFAULT_PENDING_PAYMENT_SCAN_INTERVAL, DEFAULT_RATE_PACK, DEFAULT_RECEIVABLE_SCAN_INTERVAL,
    };
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use std::collections::HashSet;

    #[test]
    fn get_all_knows_ever_present_values() {
        let subject = ConfigDaoNull::default();

        let data = subject.get_all().unwrap();

        let expected_clandestine_port = subject.data.get("clandestine_port").unwrap();
        assert_eq!(
            data,
            vec![
                ConfigDaoRecord::new(
                    "chain_name",
                    Some(Chain::default().rec().literal_identifier),
                    false
                ),
                ConfigDaoRecord::new("clandestine_port", Some(expected_clandestine_port), false),
                ConfigDaoRecord::new("gas_price", Some("1"), false),
                ConfigDaoRecord::new(
                    "start_block",
                    Some(&ETH_MAINNET_CONTRACT_CREATION_BLOCK.to_string()),
                    false
                ),
            ]
        )
    }

    #[test]
    fn get_works() {
        let subject = ConfigDaoNull::default();

        assert_eq!(
            subject.get("chain_name").unwrap(),
            ConfigDaoRecord::new(
                "chain_name",
                Some(Chain::default().rec().literal_identifier),
                false
            )
        );
        assert_eq!(
            subject.get("clandestine_port").unwrap(),
            ConfigDaoRecord::new(
                "clandestine_port",
                Some(subject.data.get("clandestine_port").unwrap()),
                false
            )
        );
        assert_eq!(
            subject.get("gas_price").unwrap(),
            ConfigDaoRecord::new("gas_price", Some("1"), false)
        );
        assert_eq!(
            subject.get("start_block").unwrap(),
            ConfigDaoRecord::new(
                "start_block",
                Some(&ETH_MAINNET_CONTRACT_CREATION_BLOCK.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("booga").unwrap(),
            ConfigDaoRecord::new("booga", None, false)
        );
        assert_eq!(
            subject.get("seed").unwrap(),
            ConfigDaoRecord::new("seed", None, true)
        );
        assert_eq!(
            subject.get("balance_decreases_for_sec").unwrap(),
            ConfigDaoRecord::new(
                "balance_decreases_for_sec",
                Some(&DEFAULT_PAYMENT_CURVES.balance_decreases_for_sec.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("balance_to_decrease_from_gwei").unwrap(),
            ConfigDaoRecord::new(
                "balance_to_decrease_from_gwei",
                Some(
                    &DEFAULT_PAYMENT_CURVES
                        .balance_to_decrease_from_gwei
                        .to_string()
                ),
                false
            )
        );
        assert_eq!(
            subject.get("exit_byte_rate").unwrap(),
            ConfigDaoRecord::new(
                "exit_byte_rate",
                Some(&DEFAULT_RATE_PACK.exit_byte_rate.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("exit_service_rate").unwrap(),
            ConfigDaoRecord::new(
                "exit_service_rate",
                Some(&DEFAULT_RATE_PACK.exit_service_rate.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("payable_scan_interval").unwrap(),
            ConfigDaoRecord::new(
                "payable_scan_interval",
                Some(&DEFAULT_PAYABLE_SCAN_INTERVAL.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("payment_grace_before_ban_sec").unwrap(),
            ConfigDaoRecord::new(
                "payment_grace_before_ban_sec",
                Some(
                    &DEFAULT_PAYMENT_CURVES
                        .payment_grace_before_ban_sec
                        .to_string()
                ),
                false
            )
        );
        assert_eq!(
            subject.get("payment_suggested_after_sec").unwrap(),
            ConfigDaoRecord::new(
                "payment_suggested_after_sec",
                Some(
                    &DEFAULT_PAYMENT_CURVES
                        .payment_suggested_after_sec
                        .to_string()
                ),
                false
            )
        );
        assert_eq!(
            subject.get("pending_payment_scan_interval").unwrap(),
            ConfigDaoRecord::new(
                "pending_payment_scan_interval",
                Some(&DEFAULT_PENDING_PAYMENT_SCAN_INTERVAL.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("permanent_debt_allowed_gwei").unwrap(),
            ConfigDaoRecord::new(
                "permanent_debt_allowed_gwei",
                Some(
                    &DEFAULT_PAYMENT_CURVES
                        .permanent_debt_allowed_gwei
                        .to_string()
                ),
                false
            )
        );
        assert_eq!(
            subject.get("receivable_scan_interval").unwrap(),
            ConfigDaoRecord::new(
                "receivable_scan_interval",
                Some(&DEFAULT_RECEIVABLE_SCAN_INTERVAL.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("routing_byte_rate").unwrap(),
            ConfigDaoRecord::new(
                "routing_byte_rate",
                Some(&DEFAULT_RATE_PACK.routing_byte_rate.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("routing_service_rate").unwrap(),
            ConfigDaoRecord::new(
                "routing_service_rate",
                Some(&DEFAULT_RATE_PACK.routing_service_rate.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("unban_when_balance_below_gwei").unwrap(),
            ConfigDaoRecord::new(
                "unban_when_balance_below_gwei",
                Some(
                    &DEFAULT_PAYMENT_CURVES
                        .unban_when_balance_below_gwei
                        .to_string()
                ),
                false
            )
        )
    }

    #[test]
    fn encrypted_rows_are_encrypted() {
        let subject = ConfigDaoNull::default();

        let results = ENCRYPTED_ROWS
            .iter()
            .map(|name| subject.get(*name))
            .collect_vec();

        results.into_iter().for_each(|result| {
            let rec = result.unwrap();
            assert_eq!(rec.value_opt, None);
            assert_eq!(rec.encrypted, true);
        })
    }

    #[test]
    fn encrypted_rows_constant_is_correct() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dao_null",
            "encrypted_rows_constant_is_correct",
        );
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&data_dir, true, MigratorConfig::test_default())
            .unwrap();
        let real_config_dao = ConfigDaoReal::new(conn);
        let records = real_config_dao.get_all().unwrap();
        let expected_encrypted_names = records
            .into_iter()
            .filter(|record| record.encrypted)
            .map(|record| record.name.clone())
            .collect::<HashSet<String>>();

        let actual_encrypted_names = ENCRYPTED_ROWS
            .iter()
            .map(|name| name.to_string())
            .collect::<HashSet<String>>();

        assert_eq!(actual_encrypted_names, expected_encrypted_names);
    }
}
