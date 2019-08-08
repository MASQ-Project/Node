// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::bootstrapper::RealUser;
use crate::config_dao::{ConfigDao, ConfigDaoReal};
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::multi_config::{CommandLineVcl, EnvironmentVcl, MultiConfig, VirtualCommandLine};
use crate::node_configurator::{app_head, data_directory_arg, real_user_arg};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::sub_lib::main_tools::StdStreams;
use clap::{value_t, Arg};
use serde_json::json;
use serde_json::{Map, Value};
use std::path::PathBuf;

const DUMP_CONFIG_HELP: &str =
    "Dump the configuration of SubstratumNode to stdout in JSON. Used chiefly by UIs.";

pub fn dump_config(args: &Vec<String>, streams: &mut StdStreams) -> i32 {
    let (data_directory, real_user) = distill_args(args);
    PrivilegeDropperReal::new().drop_privileges(&real_user);
    let config_dao = make_config_dao(&data_directory);
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
        match value {
            None => map.insert(name, json!(null)),
            Some(value) => map.insert(name, json!(value)),
        };
    });
    let value = Value::Object(map);
    serde_json::to_string_pretty(&value).expect("Couldn't serialize configuration to JSON")
}

fn make_config_dao(data_directory: &PathBuf) -> ConfigDaoReal {
    let conn = DbInitializerReal::new()
        .initialize(&data_directory)
        .unwrap_or_else(|e| {
            panic!(
                "Can't initialize database at {:?}: {:?}",
                data_directory.join(DATABASE_FILE),
                e
            )
        });
    ConfigDaoReal::new(conn)
}

fn distill_args(args: &Vec<String>) -> (PathBuf, RealUser) {
    let app = app_head()
        .arg(
            Arg::with_name("dump-config")
                .long("dump-config")
                .required(true)
                .takes_value(false)
                .help(DUMP_CONFIG_HELP),
        )
        .arg(data_directory_arg())
        .arg(real_user_arg());
    let vcls: Vec<Box<VirtualCommandLine>> = vec![
        Box::new(CommandLineVcl::new(args.clone())),
        Box::new(EnvironmentVcl::new(&app)),
    ];
    let multi_config = MultiConfig::new(&app, vcls);
    let data_dir =
        value_m!(multi_config, "data-directory", PathBuf).expect("data-directory is not defaulted");
    let real_user = value_m!(multi_config, "real-user", RealUser).unwrap_or_default();
    (data_dir, real_user.populate())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
    use crate::database::db_initializer::ROPSTEN_CONTRACT_CREATION_BLOCK;
    use crate::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
    use crate::sub_lib::cryptde::PlainData;
    use crate::test_utils::{ensure_node_home_directory_exists, ArgsBuilder, FakeStreamHolder};

    #[test]
    fn dump_config_creates_database_if_nonexistent() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_creates_database_if_nonexistent",
        );
        let mut holder = FakeStreamHolder::new();

        let result = dump_config(
            &ArgsBuilder::new()
                .param("--data-directory", data_dir.to_str().unwrap())
                .param("--real-user", "123::")
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
        let expected_value = json! ({
           "clandestine_port": actual_map.get ("clandestine_port"),
           "consuming_wallet_derivation_path": null,
           "consuming_wallet_public_key": null,
           "earning_wallet_address": null,
           "gas_price": "1",
           "schema_version": CURRENT_SCHEMA_VERSION,
           "seed": null,
           "start_block": &ROPSTEN_CONTRACT_CREATION_BLOCK.to_string(),
        });
        assert_eq!(actual_value, expected_value);
    }

    #[test]
    fn dump_config_dumps_existing_database() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::new().initialize(&data_dir).unwrap();
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
                .opt("--dump-config")
                .into(),
            &mut holder.streams(),
        );

        assert_eq!(result, 0);
        let output = holder.stdout.get_string();
        let actual_value: Value = serde_json::from_str(&output).unwrap();
        let expected_value = json! ({
           "clandestine_port": "3456",
           "consuming_wallet_derivation_path": null,
           "consuming_wallet_public_key": "01020304",
           "earning_wallet_address": "0x0123456789012345678901234567890123456789",
           "gas_price": "1",
           "schema_version": CURRENT_SCHEMA_VERSION,
           "seed": null,
           "start_block": &ROPSTEN_CONTRACT_CREATION_BLOCK.to_string(),
        });
        assert_eq!(actual_value, expected_value);
    }
}
