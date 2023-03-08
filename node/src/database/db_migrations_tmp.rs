// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use crate::accountant::dao_utils::{from_time_t, to_time_t};
    use crate::blockchain::bip39::Bip39;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, ExternalData,
        CURRENT_SCHEMA_VERSION, DATABASE_FILE,
    };
    use crate::database::db_migrations::{
        DBMigrationUtilities, DBMigrationUtilitiesReal, DatabaseMigration, DbMigrator,
        MigDeclarationUtilities, Migrate_0_to_1, StatementObject, StatementWithRusqliteParams,
    };
    use crate::database::db_migrations::{DBMigratorInnerConfiguration, DbMigratorReal};
    use crate::db_config::db_encryption_layer::DbEncryptionLayer;
    use crate::db_config::persistent_configuration::{
        PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::db_config::typed_config_layer::encode_bytes;
    use crate::sub_lib::accountant::{DEFAULT_PAYMENT_THRESHOLDS, DEFAULT_SCAN_INTERVALS};
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::database_utils::{
        assert_create_table_stm_contains_all_parts,
        assert_index_stm_is_coupled_with_right_parameter, assert_no_index_exists_for_table,
        assert_table_does_not_exist, bring_db_0_back_to_life_and_return_connection,
        make_external_data,
    };
    use crate::test_utils::database_utils::{assert_table_created_as_strict, retrieve_config_row};
    use crate::test_utils::make_wallet;
    use bip39::{Language, Mnemonic, MnemonicType, Seed};
    use ethereum_types::BigEndianHash;
    use itertools::Itertools;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::{derivation_path, NeighborhoodModeLight};
    use rand::Rng;
    use rusqlite::types::Value::Null;
    use rusqlite::{Connection, Error, OptionalExtension, Row, ToSql, Transaction};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::fs::create_dir_all;
    use std::iter::once;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use tiny_hderive::bip32::ExtendedPrivKey;
    use web3::types::{H256, U256};




}
