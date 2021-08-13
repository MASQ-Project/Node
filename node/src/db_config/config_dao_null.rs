use crate::blockchain::blockchain_interface::MAINNET_CONTRACT_CREATION_BLOCK;
use crate::database::db_initializer::{DbInitializerReal, ENCRYPTED_ROWS};
use crate::db_config::config_dao::{
    ConfigDao, ConfigDaoError, ConfigDaoRead, ConfigDaoReadWrite, ConfigDaoRecord, ConfigDaoWrite,
};
use itertools::Itertools;
use rusqlite::Transaction;
use std::collections::HashMap;

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
        unimplemented!("Shouldn't need this")
    }
}

impl ConfigDaoReadWrite for ConfigDaoNull {}

impl Default for ConfigDaoNull {
    fn default() -> Self {
        let mut data = HashMap::new();
        data.insert("chain_name".to_string(), "mainnet".to_string());
        data.insert(
            "clandestine_port".to_string(),
            DbInitializerReal::choose_clandestine_port().to_string(),
        );
        data.insert("gas_price".to_string(), "1".to_string());
        data.insert(
            "start_block".to_string(),
            MAINNET_CONTRACT_CREATION_BLOCK.to_string(),
        );
        Self { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_all_knows_ever_present_values() {
        let subject = ConfigDaoNull::default();

        let data = subject.get_all().unwrap();

        let expected_clandestine_port = subject.data.get("clandestine_port").unwrap();
        assert_eq!(
            data,
            vec![
                ConfigDaoRecord::new("chain_name", Some("mainnet"), false),
                ConfigDaoRecord::new("clandestine_port", Some(expected_clandestine_port), false),
                ConfigDaoRecord::new("gas_price", Some("1"), false),
                ConfigDaoRecord::new(
                    "start_block",
                    Some(&MAINNET_CONTRACT_CREATION_BLOCK.to_string()),
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
            ConfigDaoRecord::new("chain_name", Some("mainnet"), false)
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
                Some(&MAINNET_CONTRACT_CREATION_BLOCK.to_string()),
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
}
