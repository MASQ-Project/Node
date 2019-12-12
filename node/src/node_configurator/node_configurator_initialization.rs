// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::node_configurator::{app_head, chain_arg, config_file_arg, db_password_arg, NodeConfigurator, DB_PASSWORD_HELP, ui_port_arg};
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use clap::{App};
use std::path::{PathBuf};

#[derive(Default, Clone, PartialEq, Debug)]
pub struct InitializationConfig {
    pub chain_id: u8,
    pub config_file: PathBuf,
    pub db_password_opt: Option<String>,
    pub ui_port: u16,
}

pub struct NodeConfiguratorInitialization {}

impl NodeConfigurator<InitializationConfig> for NodeConfiguratorInitialization {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams) -> InitializationConfig {
        let app = app();
        let multi_config = crate::node_configurator::node_configurator_standard::standard::make_service_mode_multi_config(&app, args);
        let mut config = InitializationConfig::default();
        initialization::parse_args(&multi_config, &mut config, streams);
        config
    }
}

fn app() -> App<'static, 'static> {
    app_head()
        .arg(chain_arg())
        .arg(config_file_arg())
        .arg(db_password_arg(DB_PASSWORD_HELP))
        .arg(ui_port_arg())
}

mod initialization {
    use super::*;
    use crate::multi_config::{MultiConfig};
    use crate::blockchain::blockchain_interface::chain_id_from_name;
    use crate::test_utils::DEFAULT_CHAIN_ID;

    pub fn parse_args(
        multi_config: &MultiConfig,
        config: &mut InitializationConfig,
        _streams: &mut StdStreams<'_>,
    ) {
        if let Some(chain_name) = value_m!(multi_config, "chain", String) {
            config.chain_id =
                chain_id_from_name(chain_name.as_str());
        }
        else {
            config.chain_id = DEFAULT_CHAIN_ID;
        }

        config.config_file = value_m!(multi_config, "config-file", PathBuf).expect("--config-file is not properly defaulted");

        if let Some(db_password) = value_m!(multi_config, "db-password", String) {
            config.db_password_opt = Some (db_password);
        }
        else {
            config.db_password_opt = None;
        }

        if let Some(ui_port) = value_m!(multi_config, "ui-port", u16) {
            config.ui_port = ui_port;
        }
        else {
            config.ui_port = DEFAULT_UI_PORT;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use crate::test_utils::{ensure_node_home_directory_exists, FakeStreamHolder, ArgsBuilder};
    use std::fs::File;
    use std::path::PathBuf;
    use std::io::Write;
    use crate::blockchain::blockchain_interface::chain_id_from_name;
    use crate::multi_config::{VirtualCommandLine, CommandLineVcl, MultiConfig};
    use std::str::FromStr;

    #[test]
    fn can_read_parameters_from_config_file() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator_initialization",
            "can_read_parameters_from_config_file",
        );
        let config_file_path = {
            let file_path = std::env::current_dir().unwrap().join (home_dir).join("config.toml");
            let mut config_file = File::create(file_path.clone()).unwrap();
            config_file
                .write_all(b"chain = \"ropsten\"\ndb-password = \"booga\"\nui-port = 4321\n")
                .unwrap();
            file_path
        };
        let subject = NodeConfiguratorInitialization {};

        let configuration = subject.configure(
            &vec![
                "".to_string(),
                "--config-file".to_string(), config_file_path.clone().to_str().unwrap().to_string(),
            ],
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(configuration, InitializationConfig {
            chain_id: chain_id_from_name("ropsten"),
            config_file: config_file_path,
            db_password_opt: Some("booga".to_string()),
            ui_port: 4321,
        });
    }

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new();
        let mut config = InitializationConfig::default();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&app(), vcls);

        initialization::parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config, InitializationConfig {
            chain_id: chain_id_from_name("mainnet"),
            config_file: PathBuf::from_str("config.toml").unwrap(),
            db_password_opt: None,
            ui_port: DEFAULT_UI_PORT,
        });
    }

    #[test]
    fn parse_args_creates_configuration_with_values() {
        let args = ArgsBuilder::new()
            .param("--chain", "ropsten")
            .param("--config-file", "booga.toml")
            .param("--db-password", "goober")
            .param("--ui-port", "4321");
        let mut config = InitializationConfig::default();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&app(), vcls);

        initialization::parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config, InitializationConfig {
            chain_id: chain_id_from_name("ropsten"),
            config_file: PathBuf::from_str("booga.toml").unwrap(),
            db_password_opt: Some("goober".to_string()),
            ui_port: 4321,
        });
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn configure_senses_when_user_specifies_config_file() {
        let subject = NodeConfiguratorInitialization {};
        let args = ArgsBuilder::new()
            .param("--config-file", "booga.toml"); // nonexistent config file: should stimulate panic because user-specified

        subject.configure(&args.into(), &mut FakeStreamHolder::new().streams());
    }
}
