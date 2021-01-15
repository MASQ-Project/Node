// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::bip39::Bip39;
use crate::blockchain::blockchain_interface::chain_id_from_name;
use crate::bootstrapper::RealUser;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::db_config::config_dao::{ConfigDaoRead, ConfigDaoReal, ConfigDaoRecord};
use crate::db_config::typed_config_layer::{decode_bytes, encode_bytes};
use crate::node_configurator::RealDirsWrapper;
use crate::node_configurator::{
    app_head, data_directory_from_context, real_user_data_directory_opt_and_chain_name, DirsWrapper,
};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::sub_lib::cryptde::{CryptDE, PlainData};
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::utils::make_new_multi_config;
use clap::value_t;
use clap::Arg;
use heck::MixedCase;
use masq_lib::command::StdStreams;
use masq_lib::multi_config::{CommandLineVcl, EnvironmentVcl, VirtualCommandLine};
use masq_lib::shared_schema::{
    chain_arg, data_directory_arg, db_password_arg, real_user_arg, ConfiguratorError,
    DB_PASSWORD_HELP,
};
use serde_json::json;
use serde_json::{Map, Value};
use std::path::PathBuf;

const DUMP_CONFIG_HELP: &str =
    "Dump the configuration of MASQ Node to stdout in JSON. Used chiefly by UIs.";

pub fn dump_config(args: &[String], streams: &mut StdStreams) -> Result<i32, ConfiguratorError> {
    let (real_user, data_directory, chain_id, password_opt) =
        distill_args(&RealDirsWrapper {}, args, streams)?;
    let cryptde = CryptDEReal::new(chain_id);
    PrivilegeDropperReal::new().drop_privileges(&real_user);
    let config_dao = make_config_dao(&data_directory, chain_id);
    let configuration = config_dao.get_all().expect("Couldn't fetch configuration");
    let json = configuration_to_json(configuration, password_opt, &cryptde);
    write_string(streams, json);
    Ok(0)
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

fn configuration_to_json(
    configuration: Vec<ConfigDaoRecord>,
    password_opt: Option<String>,
    cryptde: &dyn CryptDE,
) -> String {
    let mut map = Map::new();
    configuration.into_iter().for_each(|record| {
        let json_name = record.name.to_mixed_case();
        let value_opt = match (&record.value_opt, record.encrypted, &password_opt) {
            (None, _, _) => None,
            (Some(value), false, _) => Some(value.to_string()),
            (Some(value), true, None) => Some(value.to_string()),
            (Some(value), true, Some(password)) => match Bip39::decrypt_bytes(value, password) {
                Ok(decrypted_value) => Some(translate_bytes(&json_name, decrypted_value, cryptde)),
                Err(_) => Some(value.to_string()),
            },
        };
        let json_value = match value_opt {
            Some(s) => json!(s),
            None => json!(null),
        };
        map.insert(json_name, json_value);
    });
    let value: Value = Value::Object(map);
    serde_json::to_string_pretty(&value).expect("Couldn't serialize configuration to JSON")
}

fn translate_bytes(json_name: &str, input: PlainData, cryptde: &dyn CryptDE) -> String {
    let to_utf8 = |data: PlainData| {
        String::from_utf8(data.into())
            .expect("Database is corrupt: past_neighbors hex string cannot be interpreted as UTF-8")
    };
    match json_name {
        "exampleEncrypted" => encode_bytes(Some(input))
            .expect("Never happen.")
            .expect("Value disappeared"),
        "pastNeighbors" => {
            let string = to_utf8(input);
            let bytes = decode_bytes(Some(string))
                .expect("Database is corrupt: past_neighbors cannot be decoded")
                .expect("Value disappeared");
            let node_descriptors =
                serde_cbor::de::from_slice::<Vec<NodeDescriptor>>(&bytes.as_slice())
                    .expect("Database is corrupt: past_neighbors contains bad CBOR");
            node_descriptors
                .into_iter()
                .map(|nd| nd.to_string(cryptde))
                .collect::<Vec<String>>()
                .join(",")
        }
        _ => to_utf8(input),
    }
}

fn make_config_dao(data_directory: &PathBuf, chain_id: u8) -> ConfigDaoReal {
    let conn = DbInitializerReal::new()
        .initialize(&data_directory, chain_id, true) // TODO: Probably should be false
        .unwrap_or_else(|e| {
            panic!(
                "Can't initialize database at {:?}: {:?}",
                data_directory.join(DATABASE_FILE),
                e
            )
        });
    ConfigDaoReal::new(conn)
}

fn distill_args(
    dirs_wrapper: &dyn DirsWrapper,
    args: &[String],
    streams: &mut StdStreams,
) -> Result<(RealUser, PathBuf, u8, Option<String>), ConfiguratorError> {
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
        .arg(real_user_arg())
        .arg(db_password_arg(DB_PASSWORD_HELP));
    let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
        Box::new(CommandLineVcl::new(args.to_vec())),
        Box::new(EnvironmentVcl::new(&app)),
    ];
    let multi_config = make_new_multi_config(&app, vcls, streams)?;
    let (real_user, data_directory_opt, chain_name) =
        real_user_data_directory_opt_and_chain_name(dirs_wrapper, &multi_config);
    let directory =
        data_directory_from_context(dirs_wrapper, &real_user, &data_directory_opt, &chain_name);
    let password_opt = value_m!(multi_config, "db-password", String);
    Ok((
        real_user,
        directory,
        chain_id_from_name(&chain_name),
        password_opt,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
    use crate::blockchain::blockchain_interface::{
        chain_id_from_name, contract_creation_block_from_chain_id,
    };
    use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
    use crate::db_config::persistent_configuration::{
        PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::db_config::typed_config_layer::encode_bytes;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::neighborhood::NodeDescriptor;
    use crate::test_utils::{main_cryptde, ArgsBuilder};
    use bip39::{Language, MnemonicType, Seed};
    use masq_lib::test_utils::environment_guard::ClapGuard;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_exists, DEFAULT_CHAIN_ID, TEST_DEFAULT_CHAIN_NAME,
    };
    use masq_lib::utils::derivation_path;

    #[test]
    fn dump_config_creates_database_if_nonexistent() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_creates_database_if_nonexistent",
        )
        .join("Substratum")
        .join(TEST_DEFAULT_CHAIN_NAME);
        let mut holder = FakeStreamHolder::new();
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN_NAME)
            .opt("--dump-config")
            .into();

        let result = dump_config(args_vec.as_slice(), &mut holder.streams()).unwrap();

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
           "exampleEncrypted": null,
           "gasPrice": "1",
           "pastNeighbors": null,
           "schemaVersion": CURRENT_SCHEMA_VERSION,
           "seed": null,
           "startBlock": &contract_creation_block_from_chain_id(chain_id_from_name(TEST_DEFAULT_CHAIN_NAME)).to_string(),
        });
        assert_eq!(actual_value, expected_value);
    }

    #[test]
    fn dump_config_dumps_existing_database_without_password() {
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_without_password",
        )
        .join("MASQ")
        .join(TEST_DEFAULT_CHAIN_NAME);
        let seed = Seed::new(
            &Bip39::mnemonic(MnemonicType::Words24, Language::English),
            "passphrase",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::new()
                .initialize(&data_dir, DEFAULT_CHAIN_ID, true)
                .unwrap();
            let mut persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.change_password(None, "password").unwrap();
            persistent_config
                .set_wallet_info(
                    &seed,
                    &derivation_path(4, 4),
                    "0x0123456789012345678901234567890123456789",
                    "password",
                )
                .unwrap();
            persistent_config.set_clandestine_port(3456).unwrap();
            persistent_config
                .set_past_neighbors(
                    Some(vec![
                        NodeDescriptor::from_str(main_cryptde(), "QUJDREVGRw@1.2.3.4:1234")
                            .unwrap(),
                        NodeDescriptor::from_str(main_cryptde(), "QkNERUZHSA@2.3.4.5:2345")
                            .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN_NAME)
            .opt("--dump-config")
            .into();

        let result = dump_config(args_vec.as_slice(), &mut holder.streams()).unwrap();

        assert_eq!(result, 0);
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::new()
            .initialize(&data_dir, DEFAULT_CHAIN_ID, false)
            .unwrap();
        let dao = ConfigDaoReal::new(conn);
        let check = |key: &str, expected_value: &str| {
            let actual_value = match map.get(key).unwrap() {
                Value::String(s) => s,
                x => panic!("Expected JSON string; found {:?}", x),
            };
            assert_eq!(actual_value, expected_value);
        };
        check("clandestinePort", "3456");
        check("consumingWalletDerivationPath", &derivation_path(4, 4));
        check(
            "earningWalletAddress",
            "0x0123456789012345678901234567890123456789",
        );
        check("gasPrice", "1");
        check(
            "pastNeighbors",
            &dao.get("past_neighbors").unwrap().value_opt.unwrap(),
        );
        check("schemaVersion", CURRENT_SCHEMA_VERSION);
        check(
            "startBlock",
            &contract_creation_block_from_chain_id(chain_id_from_name(TEST_DEFAULT_CHAIN_NAME))
                .to_string(),
        );
        check(
            "exampleEncrypted",
            &dao.get("example_encrypted").unwrap().value_opt.unwrap(),
        );
        check("seed", &dao.get("seed").unwrap().value_opt.unwrap());
    }

    #[test]
    fn dump_config_dumps_existing_database_with_correct_password() {
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_with_correct_password",
        )
        .join("MASQ")
        .join(TEST_DEFAULT_CHAIN_NAME);
        let seed = Seed::new(
            &Bip39::mnemonic(MnemonicType::Words24, Language::English),
            "passphrase",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::new()
                .initialize(&data_dir, DEFAULT_CHAIN_ID, true)
                .unwrap();
            let mut persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.change_password(None, "password").unwrap();
            persistent_config
                .set_wallet_info(
                    &seed,
                    &derivation_path(4, 4),
                    "0x0123456789012345678901234567890123456789",
                    "password",
                )
                .unwrap();
            persistent_config.set_clandestine_port(3456).unwrap();
            persistent_config
                .set_past_neighbors(
                    Some(vec![
                        NodeDescriptor::from_str(
                            main_cryptde(),
                            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234",
                        )
                        .unwrap(),
                        NodeDescriptor::from_str(
                            main_cryptde(),
                            "QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345",
                        )
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN_NAME)
            .param("--db-password", "password")
            .opt("--dump-config")
            .into();

        let result = dump_config(args_vec.as_slice(), &mut holder.streams()).unwrap();

        assert_eq!(result, 0);
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::new()
            .initialize(&data_dir, DEFAULT_CHAIN_ID, false)
            .unwrap();
        let dao = Box::new(ConfigDaoReal::new(conn));
        let check = |key: &str, expected_value: &str| {
            let actual_value = match map.get(key).unwrap() {
                Value::String(s) => s,
                x => panic!("Expected JSON string; found {:?}", x),
            };
            assert_eq!(actual_value, expected_value);
        };
        check("clandestinePort", "3456");
        check("consumingWalletDerivationPath", &derivation_path(4, 4));
        check(
            "earningWalletAddress",
            "0x0123456789012345678901234567890123456789",
        );
        check("gasPrice", "1");
        check("pastNeighbors", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234,QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345");
        check("schemaVersion", CURRENT_SCHEMA_VERSION);
        check(
            "startBlock",
            &contract_creation_block_from_chain_id(chain_id_from_name(TEST_DEFAULT_CHAIN_NAME))
                .to_string(),
        );
        let expected_ee_entry = dao.get("example_encrypted").unwrap().value_opt.unwrap();
        let expected_ee_decrypted = Bip39::decrypt_bytes(&expected_ee_entry, "password").unwrap();
        let expected_ee_string = encode_bytes(Some(expected_ee_decrypted)).unwrap().unwrap();
        check("exampleEncrypted", &expected_ee_string);
        check(
            "seed",
            &encode_bytes(Some(PlainData::new(seed.as_ref())))
                .unwrap()
                .unwrap(),
        );
    }

    #[test]
    fn dump_config_dumps_existing_database_with_incorrect_password() {
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_with_incorrect_password",
        )
        .join("MASQ")
        .join(TEST_DEFAULT_CHAIN_NAME);
        let seed = Seed::new(
            &Bip39::mnemonic(MnemonicType::Words24, Language::English),
            "passphrase",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::new()
                .initialize(&data_dir, DEFAULT_CHAIN_ID, true)
                .unwrap();
            let mut persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.change_password(None, "password").unwrap();
            persistent_config
                .set_wallet_info(
                    &seed,
                    &derivation_path(4, 4),
                    "0x0123456789012345678901234567890123456789",
                    "password",
                )
                .unwrap();
            persistent_config.set_clandestine_port(3456).unwrap();
            persistent_config
                .set_past_neighbors(
                    Some(vec![
                        NodeDescriptor::from_str(
                            main_cryptde(),
                            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234",
                        )
                        .unwrap(),
                        NodeDescriptor::from_str(
                            main_cryptde(),
                            "QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345",
                        )
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN_NAME)
            .param("--db-password", "incorrect")
            .opt("--dump-config")
            .into();

        let result = dump_config(args_vec.as_slice(), &mut holder.streams()).unwrap();

        assert_eq!(result, 0);
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::new()
            .initialize(&data_dir, DEFAULT_CHAIN_ID, false)
            .unwrap();
        let dao = Box::new(ConfigDaoReal::new(conn));
        let check = |key: &str, expected_value: &str| {
            let actual_value = match map.get(key).unwrap() {
                Value::String(s) => s,
                x => panic!("Expected JSON string; found {:?}", x),
            };
            assert_eq!(actual_value, expected_value);
        };
        check("clandestinePort", "3456");
        check("consumingWalletDerivationPath", &derivation_path(4, 4));
        check(
            "earningWalletAddress",
            "0x0123456789012345678901234567890123456789",
        );
        check("gasPrice", "1");
        check(
            "pastNeighbors",
            &dao.get("past_neighbors").unwrap().value_opt.unwrap(),
        );
        check("schemaVersion", CURRENT_SCHEMA_VERSION);
        check(
            "startBlock",
            &contract_creation_block_from_chain_id(chain_id_from_name(TEST_DEFAULT_CHAIN_NAME))
                .to_string(),
        );
        check(
            "exampleEncrypted",
            &dao.get("example_encrypted").unwrap().value_opt.unwrap(),
        );
        check("seed", &dao.get("seed").unwrap().value_opt.unwrap());
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: past_neighbors hex string cannot be interpreted as UTF-8"
    )]
    fn decode_bytes_handles_decode_error_for_past_neighbors() {
        let cryptde = main_cryptde();
        let data = PlainData::new(&[192, 193]);

        let _ = translate_bytes("pastNeighbors", data, cryptde);
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: past_neighbors cannot be decoded")]
    fn decode_bytes_handles_utf8_error_for_past_neighbors() {
        let cryptde = main_cryptde();
        let data = PlainData::new(b"invalid hex");

        let _ = translate_bytes("pastNeighbors", data, cryptde);
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: past_neighbors contains bad CBOR")]
    fn decode_bytes_handles_bad_cbor_for_past_neighbors() {
        let cryptde = main_cryptde();
        let data = PlainData::new(b"AABBCC");

        let _ = translate_bytes("pastNeighbors", data, cryptde);
    }
}
