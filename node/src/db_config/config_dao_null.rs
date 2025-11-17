// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_initializer::DbInitializerReal;
use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, ConfigDaoRecord};
use crate::neighborhood::DEFAULT_MIN_HOPS;
use crate::sub_lib::accountant::{DEFAULT_PAYMENT_THRESHOLDS, DEFAULT_SCAN_INTERVALS};
use crate::sub_lib::neighborhood::{DEFAULT_RATE_PACK, DEFAULT_RATE_PACK_LIMITS};
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::{CURRENT_SCHEMA_VERSION, DEFAULT_GAS_PRICE};
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

#[derive(Debug, PartialEq, Eq)]
pub struct ConfigDaoNull {
    data: HashMap<String, (Option<String>, bool)>,
}

impl ConfigDao for ConfigDaoNull {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        let keys = self.data.keys().sorted();
        Ok(keys
            .map(|key| {
                let value_pair = self.data.get(key).expect("Value disappeared");
                ConfigDaoRecord::new_owned(key.to_string(), value_pair.0.clone(), value_pair.1)
            })
            .collect())
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        match self.data.get(name) {
            None => Err(ConfigDaoError::NotPresent),
            Some((value_opt, encrypted)) => Ok(ConfigDaoRecord::new_owned(
                name.to_string(),
                value_opt.clone(),
                *encrypted,
            )),
        }
    }

    fn set(&self, _name: &str, _value: Option<String>) -> Result<(), ConfigDaoError> {
        Ok(())
    }

    fn set_by_guest_transaction(
        &self,
        _txn: &mut TransactionSafeWrapper,
        _name: &str,
        _value: Option<String>,
    ) -> Result<(), ConfigDaoError> {
        Ok(())
    }
}

impl Default for ConfigDaoNull {
    fn default() -> Self {
        let mut data = HashMap::new();
        data.insert(
            "chain_name".to_string(),
            (
                Some(Chain::default().rec().literal_identifier.to_string()),
                false,
            ),
        );
        data.insert(
            "clandestine_port".to_string(),
            (
                Some(DbInitializerReal::choose_clandestine_port().to_string()),
                false,
            ),
        );
        data.insert("last_cryptde".to_string(), (None, true));
        data.insert(
            "gas_price".to_string(),
            (Some(DEFAULT_GAS_PRICE.to_string()), false),
        );
        data.insert(
            "start_block".to_string(),
            (
                Some(Chain::default().rec().contract_creation_block.to_string()),
                false,
            ),
        );
        data.insert("consuming_wallet_private_key".to_string(), (None, true));
        data.insert("example_encrypted".to_string(), (None, true));
        data.insert(
            "neighborhood_mode".to_string(),
            (Some("standard".to_string()), false),
        );
        data.insert("blockchain_service_url".to_string(), (None, false));
        data.insert("past_neighbors".to_string(), (None, true));
        data.insert("mapping_protocol".to_string(), (None, false));
        data.insert(
            "min_hops".to_string(),
            (Some(DEFAULT_MIN_HOPS.to_string()), false),
        );
        data.insert("earning_wallet_address".to_string(), (None, false));
        data.insert(
            "schema_version".to_string(),
            (Some(format!("{}", CURRENT_SCHEMA_VERSION)), false),
        );
        data.insert(
            "payment_thresholds".to_string(),
            (Some(DEFAULT_PAYMENT_THRESHOLDS.to_string()), false),
        );
        data.insert(
            "rate_pack".to_string(),
            (Some(DEFAULT_RATE_PACK.to_string()), false),
        );
        data.insert(
            "rate_pack_limits".to_string(),
            (
                Some(DEFAULT_RATE_PACK_LIMITS.rate_pack_limits_parameter()),
                false,
            ),
        );
        data.insert(
            "scan_intervals".to_string(),
            (Some(DEFAULT_SCAN_INTERVALS.to_string()), false),
        );
        data.insert("max_block_count".to_string(), (None, false));
        Self { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::DbInitializationConfig;
    use crate::database::db_initializer::DbInitializer;
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;
    use crate::db_config::config_dao::ConfigDaoReal;
    use crate::neighborhood::DEFAULT_MIN_HOPS;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::{DEFAULT_CHAIN, ETH_MAINNET_CONTRACT_CREATION_BLOCK};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn get_works() {
        let subject = ConfigDaoNull::default();

        assert_eq!(subject.get("booga"), Err(ConfigDaoError::NotPresent));
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
            ConfigDaoRecord::new_owned(
                "clandestine_port".to_string(),
                subject.data.get("clandestine_port").unwrap().0.clone(),
                false
            )
        );
        assert_eq!(
            subject.get("consuming_wallet_private_key").unwrap(),
            ConfigDaoRecord::new("consuming_wallet_private_key", None, true)
        );
        assert_eq!(
            subject.get("gas_price").unwrap(),
            ConfigDaoRecord::new("gas_price", Some("1"), false)
        );
        assert_eq!(
            subject.get("min_hops").unwrap(),
            ConfigDaoRecord::new("min_hops", Some(&DEFAULT_MIN_HOPS.to_string()), false)
        );
        assert_eq!(
            subject.get("payment_thresholds").unwrap(),
            ConfigDaoRecord::new(
                "payment_thresholds",
                Some(&DEFAULT_PAYMENT_THRESHOLDS.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("rate_pack").unwrap(),
            ConfigDaoRecord::new("rate_pack", Some(&DEFAULT_RATE_PACK.to_string()), false)
        );
        assert_eq!(
            subject.get("scan_intervals").unwrap(),
            ConfigDaoRecord::new(
                "scan_intervals",
                Some(&DEFAULT_SCAN_INTERVALS.to_string()),
                false
            )
        );
        assert_eq!(
            subject.get("start_block").unwrap(),
            ConfigDaoRecord::new(
                "start_block",
                Some(&DEFAULT_CHAIN.rec().contract_creation_block.to_string()),
                false
            )
        );
    }

    #[test]
    fn all_configurable_items_are_included() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dao_null",
            "all_configurable_items_are_included",
        );
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(&data_dir, DbInitializationConfig::test_default())
            .unwrap();
        let real_config_dao = ConfigDaoReal::new(conn);
        let subject = ConfigDaoNull::default();
        let real_pairs = return_parameter_pairs(&real_config_dao);

        let null_pairs = return_parameter_pairs(&subject);

        assert_eq!(null_pairs, real_pairs);
    }

    fn return_parameter_pairs(dao: &dyn ConfigDao) -> Vec<(String, bool)> {
        dao.get_all()
            .unwrap()
            .into_iter()
            .map(|r| (r.name, r.encrypted))
            .sorted_by_key(|pair| pair.0.clone())
            .collect::<Vec<(String, bool)>>()
    }

    #[test]
    fn values_are_correct() {
        let subject = ConfigDaoNull::default();

        let value_pairs = subject
            .get_all()
            .unwrap()
            .into_iter()
            .map(|r| (r.name, r.value_opt))
            .collect::<Vec<(String, Option<String>)>>()
            .sort_by_key(|p| p.0.clone());

        let expected_pairs = vec![
            (
                "chain_name",
                Some(Chain::default().rec().literal_identifier),
            ),
            (
                "clandestine_port",
                Some(format!("{}", DbInitializerReal::choose_clandestine_port()).as_str()),
            ),
            ("gas_price", Some("1")),
            (
                "start_block",
                Some(ETH_MAINNET_CONTRACT_CREATION_BLOCK.to_string().as_str()),
            ),
            ("consuming_wallet_private_key", None),
            ("example_encrypted", None),
            ("neighborhood_mode", Some("standard")),
            ("blockchain_service_url", None),
            ("past_neighbors", None),
            ("mapping_protocol", None),
            ("earning_wallet_address", None),
            (
                "schema_version",
                Some(format!("{}", CURRENT_SCHEMA_VERSION).as_str()),
            ),
            ("max_block_count", None),
        ]
        .into_iter()
        .map(|(k, v_opt)| (k.to_string(), v_opt.map(|v| v.to_string())))
        .collect::<Vec<(String, Option<String>)>>()
        .sort_by_key(|p| p.0.clone());

        assert_eq!(value_pairs, expected_pairs);
    }

    #[test]
    fn set_works_simple() {
        let subject = ConfigDaoNull::default();

        subject.set("param1", Some("value1".to_string())).unwrap();
        subject.set("schema_version", None).unwrap();
        subject
            .set("schema_version", Some("456".to_string()))
            .unwrap();

        let subject_data_sorted = subject.data.iter().sorted().collect::<Vec<(_, _)>>();
        let comparison_subject_data_sorted = subject.data.iter().sorted().collect::<Vec<(_, _)>>();
        assert_eq!(subject_data_sorted, comparison_subject_data_sorted)
    }

    #[test]
    fn set_by_guest_transaction_works_simple() {
        let subject = ConfigDaoNull::default();
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default();
        let mut txn = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let subject_data_before_sorted = subject.data.iter().sorted().collect::<Vec<(_, _)>>();

        subject
            .set_by_guest_transaction(&mut txn, "param1", Some("value1".to_string()))
            .unwrap();
        subject
            .set_by_guest_transaction(&mut txn, "schema_version", None)
            .unwrap();
        subject
            .set_by_guest_transaction(&mut txn, "schema_version", Some("456".to_string()))
            .unwrap();

        let subject_data_after_sorted = subject.data.iter().sorted().collect::<Vec<(_, _)>>();
        assert_eq!(subject_data_after_sorted, subject_data_before_sorted)
        // Test didn't blow up so no method from the txn wrapper was called,
        // therefore we don't even have to consider committing the transaction
    }
}
