// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_initializer::{DbInitializerReal, CURRENT_SCHEMA_VERSION};
use crate::db_config::config_dao::{
    ConfigDao, ConfigDaoError, ConfigDaoRead, ConfigDaoReadWrite, ConfigDaoRecord, ConfigDaoWrite,
};
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::ETH_MAINNET_CONTRACT_CREATION_BLOCK;
use rusqlite::Transaction;
use std::collections::HashMap;

pub struct ConfigDaoNull {
    data: HashMap<String, (Option<String>, bool)>,
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
        data.insert("gas_price".to_string(), (Some("1".to_string()), false));
        data.insert(
            "start_block".to_string(),
            (Some(ETH_MAINNET_CONTRACT_CREATION_BLOCK.to_string()), false),
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
        data.insert("earning_wallet_address".to_string(), (None, false));
        data.insert(
            "schema_version".to_string(),
            (Some(format!("{}", CURRENT_SCHEMA_VERSION)), false),
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
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use std::collections::HashSet;

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
            ConfigDaoRecord::new_owned(
                "clandestine_port".to_string(),
                subject.data.get("clandestine_port").unwrap().0.clone(),
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
        assert_eq!(subject.get("booga"), Err(ConfigDaoError::NotPresent));
        assert_eq!(
            subject.get("consuming_wallet_private_key").unwrap(),
            ConfigDaoRecord::new("consuming_wallet_private_key", None, true)
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
            .initialize(&data_dir, true, MigratorConfig::test_default())
            .unwrap();
        let real_config_dao = ConfigDaoReal::new(conn);
        let subject = ConfigDaoNull::default();
        let real_pairs = real_config_dao
            .get_all()
            .unwrap()
            .into_iter()
            .map(|r| (r.name, r.encrypted))
            .collect::<HashSet<(String, bool)>>();

        let null_pairs = subject
            .get_all()
            .unwrap()
            .into_iter()
            .map(|r| (r.name, r.encrypted))
            .collect::<HashSet<(String, bool)>>();

        assert_eq!(null_pairs, real_pairs);
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
        ]
        .into_iter()
        .map(|(k, v_opt)| (k.to_string(), v_opt.map(|v| v.to_string())))
        .collect::<Vec<(String, Option<String>)>>()
        .sort_by_key(|p| p.0.clone());

        assert_eq!(value_pairs, expected_pairs);
    }
}
