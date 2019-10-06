// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::bootstrapper::RealUser;
use crate::config_dao::{ConfigDao, ConfigDaoReal};
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::multi_config::{CommandLineVcl, EnvironmentVcl, MultiConfig, VirtualCommandLine};
use crate::node_configurator::{app_head, chain_arg, data_directory_arg, real_user_arg};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::sub_lib::main_tools::StdStreams;
use clap::Arg;
use heck::MixedCase;
use serde_json::json;
use serde_json::{Map, Value};
use std::path::PathBuf;

const DUMP_CONFIG_HELP: &str =
    "Dump the configuration of MASQ Node to stdout in JSON. Used chiefly by UIs.";

pub fn dump_config(args: &Vec<String>, streams: &mut StdStreams) -> i32 {
    let (real_user, data_directory, chain_id) = distill_args(args);
    PrivilegeDropperReal::new().drop_privileges(&real_user);
    let config_dao = make_config_dao(&data_directory, chain_id);
    let configuration = config_dao.get_all().expect("Couldn't fetch configuration");
    let json = configuration_to_json(configuration);
    write_string(streams, json);
    0
}

fn write_string(streams: &mut StdStreams, json: String) {
    streams
        .stdout
        .write_all(json.as_bytes())
        .expect("Couldn't write JSON to stdout");
    streams
        .stdout
        .flush()
        .expect("Couldn't flush JSON to stdout");
}

fn configuration_to_json(configuration: Vec<(String, Option<String>)>) -> String {
    let mut map = Map::new();
    configuration.into_iter().for_each(|(name, value)| {
        let json_name = name.to_mixed_case();
        match value {
            None => map.insert(json_name, json!(null)),
            Some(value) => map.insert(json_name, json!(value)),
        };
    });
    let value: Value = Value::Object(map);
    serde_json::to_string_pretty(&value).expect("Couldn't serialize configuration to JSON")
}

fn make_config_dao(data_directory: &PathBuf, chain_id: u8) -> ConfigDaoReal {
    let conn = DbInitializerReal::new()
        .initialize(&data_directory, chain_id)
        .unwrap_or_else(|e| {
            panic!(
                "Can't initialize database at {:?}: {:?}",
                data_directory.join(DATABASE_FILE),
                e
            )
        });
    ConfigDaoReal::new(conn)
}

fn distill_args(args: &Vec<String>) -> (RealUser, PathBuf, u8) {
    let app = app_head()
        .arg(
            Arg::with_name("dump-config")
                .long("dump-config")
                .required(true)
                .takes_value(false)
                .help(DUMP_CONFIG_HELP),
        )
        .arg(chain_arg())
        .arg(data_directory_arg())
        .arg(real_user_arg());
    let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
        Box::new(CommandLineVcl::new(args.clone())),
        Box::new(EnvironmentVcl::new(&app)),
    ];
    let multi_config = MultiConfig::new(&app, vcls);
    crate::node_configurator::real_user_data_directory_and_chain_id(&multi_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::{
        chain_id_from_name, contract_creation_block_from_chain_id, DEFAULT_CHAIN_NAME,
    };
    use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
    use crate::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
    use crate::sub_lib::cryptde::PlainData;
    use crate::test_utils::{
        ensure_node_home_directory_exists, ArgsBuilder, FakeStreamHolder, DEFAULT_CHAIN_ID,
    };

    #[test]
    fn dump_config_creates_database_if_nonexistent() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_creates_database_if_nonexistent",
        )
        .join("Substratum")
        .join(DEFAULT_CHAIN_NAME);
        let mut holder = FakeStreamHolder::new();

        let result = dump_config(
            &ArgsBuilder::new()
                .param("--data-directory", data_dir.to_str().unwrap())
                .param("--real-user", "123::")
                .param("--chain", DEFAULT_CHAIN_NAME)
                .opt("--dump-config")
                .into(),
            &mut holder.streams(),
        );

        assert_eq!(result, 0);
        let output = holder.stdout.get_string();
        let actual_value: Value = serde_json::from_str(&output).unwrap();
        let actual_map = match &actual_value {
            Value::Object(map) => map,
            other => panic!("Was expecting Value::Object, got {:?} instead", other),
        };
        let expected_value = json!({
           "clandestinePort": actual_map.get ("clandestinePort"),
           "consumingWalletDerivationPath": null,
           "consumingWalletPublicKey": null,
           "earningWalletAddress": null,
           "gasPrice": "1",
           "schemaVersion": CURRENT_SCHEMA_VERSION,
           "seed": null,
           "startBlock": &contract_creation_block_from_chain_id(chain_id_from_name(DEFAULT_CHAIN_NAME)).to_string(),
        });
        assert_eq!(actual_value, expected_value);
    }

    #[test]
    fn dump_config_dumps_existing_database() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database",
        )
        .join("Substratum")
        .join(DEFAULT_CHAIN_NAME);
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::new()
                .initialize(&data_dir, DEFAULT_CHAIN_ID)
                .unwrap();
            let persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.set_consuming_wallet_public_key(&PlainData::new(&[1, 2, 3, 4]));
            persistent_config
                .set_earning_wallet_address("0x0123456789012345678901234567890123456789");
            persistent_config.set_clandestine_port(3456);
        }

        let result = dump_config(
            &ArgsBuilder::new()
                .param("--data-directory", data_dir.to_str().unwrap())
                .param("--real-user", "123::")
                .param("--chain", DEFAULT_CHAIN_NAME)
                .opt("--dump-config")
                .into(),
            &mut holder.streams(),
        );

        assert_eq!(result, 0);
        let output = holder.stdout.get_string();
        let actual_value: Value = serde_json::from_str(&output).unwrap();
        let expected_value = json!({
           "clandestinePort": "3456",
           "consumingWalletDerivationPath": null,
           "consumingWalletPublicKey": "01020304",
           "earningWalletAddress": "0x0123456789012345678901234567890123456789",
           "gasPrice": "1",
           "schemaVersion": CURRENT_SCHEMA_VERSION,
           "seed": null,
           "startBlock": &contract_creation_block_from_chain_id(chain_id_from_name(DEFAULT_CHAIN_NAME)).to_string(),
        });
        assert_eq!(actual_value, expected_value);
    }
}
