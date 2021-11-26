// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::apps::app_config_dumper;
use crate::blockchain::bip39::Bip39;
use crate::bootstrapper::RealUser;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::db_config::config_dao::{ConfigDaoRead, ConfigDaoReal, ConfigDaoRecord};
use crate::db_config::typed_config_layer::{decode_bytes, encode_bytes};
use crate::node_configurator::DirsWrapperReal;
use crate::node_configurator::{
    data_directory_from_context, real_user_with_data_directory_opt_and_chain, DirsWrapper,
};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::run_modes_factories::DumpConfigRunner;
use crate::sub_lib::cryptde::{CryptDE, PlainData};
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::utils::make_new_multi_config;
use clap::value_t;
use heck::MixedCase;
use masq_lib::command::StdStreams;
use masq_lib::multi_config::{CommandLineVcl, EnvironmentVcl, VirtualCommandLine};
use masq_lib::shared_schema::ConfiguratorError;
use serde_json::json;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

use masq_lib::blockchains::chains::Chain;
#[cfg(test)]
use std::any::Any;

pub struct DumpConfigRunnerReal;

impl DumpConfigRunner for DumpConfigRunnerReal {
    fn go(&self, streams: &mut StdStreams, args: &[String]) -> Result<(), ConfiguratorError> {
        let (real_user, data_directory, chain, password_opt) =
            distill_args(&DirsWrapperReal {}, args)?;
        let cryptde = CryptDEReal::new(chain);
        PrivilegeDropperReal::new().drop_privileges(&real_user);
        let config_dao = make_config_dao(&data_directory, chain);
        let configuration = config_dao.get_all().expect("Couldn't fetch configuration");
        let json = configuration_to_json(configuration, password_opt, &cryptde);
        write_string(streams, json);
        Ok(())
    }

    as_any_impl!();
}

fn write_string(streams: &mut StdStreams, json: String) {
    short_writeln!(streams.stdout, "{}", json);
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
                serde_cbor::de::from_slice::<Vec<NodeDescriptor>>(bytes.as_slice())
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

fn make_config_dao(data_directory: &Path, chain: Chain) -> ConfigDaoReal {
    let conn = DbInitializerReal::default()
        .initialize(data_directory, chain, true) // TODO: Probably should be false
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
) -> Result<(RealUser, PathBuf, Chain, Option<String>), ConfiguratorError> {
    let app = app_config_dumper();
    let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
        Box::new(CommandLineVcl::new(args.to_vec())),
        Box::new(EnvironmentVcl::new(&app)),
    ];
    let multi_config = make_new_multi_config(&app, vcls)?;
    let (real_user, data_directory_opt, chain) =
        real_user_with_data_directory_opt_and_chain(dirs_wrapper, &multi_config);
    let directory =
        data_directory_from_context(dirs_wrapper, &real_user, &data_directory_opt, chain);
    let password_opt = value_m!(multi_config, "db-password", String);
    Ok((real_user, directory, chain, password_opt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
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
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::derivation_path;

    #[test]
    fn dump_config_creates_database_if_nonexistent() {
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_creates_database_if_nonexistent",
        )
        .join("MASQ")
        .join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        let mut holder = FakeStreamHolder::new();
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN.rec().literal_identifier)
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal;

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok());
        let output = holder.stdout.get_string();
        let actual_value: Value = serde_json::from_str(&output).unwrap();
        let actual_map = match &actual_value {
            Value::Object(map) => map,
            other => panic!("Was expecting Value::Object, got {:?} instead", other),
        };
        let expected_value = json!({
           "chainName": TEST_DEFAULT_CHAIN.rec().literal_identifier.to_string(),
           "clandestinePort": actual_map.get ("clandestinePort"),
           "consumingWalletDerivationPath": null,
           "consumingWalletPublicKey": null,
           "earningWalletAddress": null,
           "exampleEncrypted": null,
           "gasPrice": "1",
           "mappingProtocol": null,
           "pastNeighbors": null,
           "schemaVersion": CURRENT_SCHEMA_VERSION.to_string(),
           "seed": null,
           "startBlock": &TEST_DEFAULT_CHAIN.rec().contract_creation_block.to_string(),
        });
        assert_eq!(actual_value, expected_value);
        assert!(output.ends_with("\n}\n"))
    }

    #[test]
    fn dump_config_dumps_existing_database_without_password() {
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "config_dumper",
            "dump_config_dumps_existing_database_without_password",
        )
        .join("MASQ")
        .join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        let seed = Seed::new(
            &Bip39::mnemonic(MnemonicType::Words24, Language::English),
            "passphrase",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::default()
                .initialize(&data_dir, TEST_DEFAULT_CHAIN, true)
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
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QUJDREVGRw@1.2.3.4:1234",
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QkNERUZHSA@2.3.4.5:2345",
                        ))
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN.rec().literal_identifier)
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal;

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok());
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, TEST_DEFAULT_CHAIN, false)
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
        check("schemaVersion", &CURRENT_SCHEMA_VERSION.to_string());
        check(
            "startBlock",
            &TEST_DEFAULT_CHAIN.rec().contract_creation_block.to_string(),
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
        .join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        let seed = Seed::new(
            &Bip39::mnemonic(MnemonicType::Words24, Language::English),
            "passphrase",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::default()
                .initialize(&data_dir, TEST_DEFAULT_CHAIN, true)
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
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234",
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345",
                        ))
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN.rec().literal_identifier)
            .param("--db-password", "password")
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal;

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok());
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, TEST_DEFAULT_CHAIN, false)
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
        check("pastNeighbors", "masq://eth-mainnet:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234,masq://eth-mainnet:QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345");
        check("schemaVersion", &CURRENT_SCHEMA_VERSION.to_string());
        check(
            "startBlock",
            &TEST_DEFAULT_CHAIN.rec().contract_creation_block.to_string(),
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
        .join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        let seed = Seed::new(
            &Bip39::mnemonic(MnemonicType::Words24, Language::English),
            "passphrase",
        );
        let mut holder = FakeStreamHolder::new();
        {
            let conn = DbInitializerReal::default()
                .initialize(&data_dir, TEST_DEFAULT_CHAIN, true)
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
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU@1.2.3.4:1234",
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY@2.3.4.5:2345",
                        ))
                        .unwrap(),
                    ]),
                    "password",
                )
                .unwrap();
        }
        let args_vec: Vec<String> = ArgsBuilder::new()
            .param("--data-directory", data_dir.to_str().unwrap())
            .param("--real-user", "123::")
            .param("--chain", TEST_DEFAULT_CHAIN.rec().literal_identifier)
            .param("--db-password", "incorrect")
            .opt("--dump-config")
            .into();
        let subject = DumpConfigRunnerReal;

        let result = subject.go(&mut holder.streams(), args_vec.as_slice());

        assert!(result.is_ok());
        let output = holder.stdout.get_string();
        let map = match serde_json::from_str(&output).unwrap() {
            Value::Object(map) => map,
            x => panic!("Expected JSON object; found {:?}", x),
        };
        let conn = DbInitializerReal::default()
            .initialize(&data_dir, TEST_DEFAULT_CHAIN, false)
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
        check("schemaVersion", &CURRENT_SCHEMA_VERSION.to_string());
        check(
            "startBlock",
            &TEST_DEFAULT_CHAIN.rec().contract_creation_block.to_string(),
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
