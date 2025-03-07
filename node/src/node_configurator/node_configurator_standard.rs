// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::bootstrapper::BootstrapperConfig;
use crate::node_configurator::DirsWrapperReal;
use crate::node_configurator::{initialize_database, DirsWrapper, NodeConfigurator};
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::{ConfigFile, ConfiguratorError, InsecurePort, IpAddrs};
use masq_lib::shared_schema::NeighborhoodMode as SchemaNeighborhoodMode;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use log::LevelFilter;

use crate::apps::app_node;
use crate::bootstrapper::PortConfiguration;
use crate::database::db_initializer::{DbInitializationConfig, ExternalData};
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
use crate::node_configurator::unprivileged_parse_args_configuration::{
    UnprivilegedParseArgsConfiguration, UnprivilegedParseArgsConfigurationDaoReal,
};
use crate::node_configurator::{
    data_directory_from_context, determine_fundamentals, real_user_data_directory_path_and_chain,
};
use crate::server_initializer::GatheredParams;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::utils::make_new_multi_config;
use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use masq_lib::constants::{DEFAULT_UI_PORT, HTTP_PORT, TLS_PORT};
use masq_lib::multi_config::{CommandLineVcl, ConfigFileVcl, EnvironmentVcl};
use std::str::FromStr;
use itertools::Itertools;

pub struct NodeConfiguratorStandardPrivileged {
    dirs_wrapper: Box<dyn DirsWrapper>,
}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardPrivileged {
    fn configure(
        &self,
        multi_config: &MultiConfig,
    ) -> Result<BootstrapperConfig, ConfiguratorError> {
        let mut bootstrapper_config = BootstrapperConfig::new();
        establish_port_configurations(&mut bootstrapper_config);
        privileged_parse_args(
            self.dirs_wrapper.as_ref(),
            multi_config,
            &mut bootstrapper_config,
        )?;
        Ok(bootstrapper_config)
    }
}

impl Default for NodeConfiguratorStandardPrivileged {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeConfiguratorStandardPrivileged {
    pub fn new() -> Self {
        Self {
            dirs_wrapper: Box::new(DirsWrapperReal {}),
        }
    }
}

pub struct NodeConfiguratorStandardUnprivileged {
    privileged_config: BootstrapperConfig,
    logger: Logger,
}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardUnprivileged {
    fn configure(
        &self,
        multi_config: &MultiConfig,
    ) -> Result<BootstrapperConfig, ConfiguratorError> {
        let mut persistent_config = initialize_database(
            &self.privileged_config.data_directory,
            DbInitializationConfig::create_or_migrate(ExternalData::from((self, multi_config))),
        );
        let mut unprivileged_config = BootstrapperConfig::new();
        let parse_args_configurator = UnprivilegedParseArgsConfigurationDaoReal {};
        parse_args_configurator.unprivileged_parse_args(
            multi_config,
            &mut unprivileged_config,
            persistent_config.as_mut(),
            &self.logger,
        )?;
        configure_database(&unprivileged_config, persistent_config.as_mut())?;
        Ok(unprivileged_config)
    }
}

impl<'a> From<(&'a NodeConfiguratorStandardUnprivileged, &'a MultiConfig)> for ExternalData {
    fn from(tuple: (&'a NodeConfiguratorStandardUnprivileged, &'a MultiConfig)) -> ExternalData {
        let (node_configurator_standard, multi_config) = tuple;
        let (neighborhood_mode, db_password_opt) =
            collect_externals_from_multi_config(multi_config);
        ExternalData::new(
            node_configurator_standard
                .privileged_config
                .blockchain_bridge_config
                .chain,
            neighborhood_mode,
            db_password_opt,
        )
    }
}

impl NodeConfiguratorStandardUnprivileged {
    pub fn new(privileged_config: &BootstrapperConfig) -> Self {
        Self {
            privileged_config: privileged_config.clone(),
            logger: Logger::new("NodeConfiguratorStandardUnprivileged"),
        }
    }
}

fn collect_externals_from_multi_config(
    multi_config: &MultiConfig,
) -> (SchemaNeighborhoodMode, Option<String>) {
    (
        value_m!(multi_config, "neighborhood-mode", SchemaNeighborhoodMode)
            .unwrap_or(SchemaNeighborhoodMode::Standard),
        value_m!(multi_config, "db-password", String),
    )
}

pub fn server_initializer_collected_params<'a>(
    dirs_wrapper: &dyn DirsWrapper,
    args: &[String],
) -> Result<GatheredParams, ConfiguratorError> {
    let app = app_node();

    let (config_file_path, user_specified, data_directory, real_user) =
        determine_fundamentals(dirs_wrapper, &app, args)?;

    let config_file_vcl = match ConfigFileVcl::new(&config_file_path, user_specified) {
        Ok(cfv) => Box::new(cfv),
        Err(e) => return Err(ConfiguratorError::required("config-file", &e.to_string())),
    };
    let full_multi_config = make_new_multi_config(
        &app,
        vec![
            Box::new(CommandLineVcl::new(args.to_vec())),
            Box::new(EnvironmentVcl::new(&app)),
            config_file_vcl,
        ],
    )?;
    let config_file_path =
        value_m!(full_multi_config, "config-file", ConfigFile).expect("defaulted param").path;
    Ok(GatheredParams::new(
        full_multi_config,
        config_file_path,
        real_user,
        data_directory,
    ))
}

pub fn establish_port_configurations(config: &mut BootstrapperConfig) {
    config.port_configurations.insert(
        HTTP_PORT,
        PortConfiguration::new(
            vec![Box::new(HttpRequestDiscriminatorFactory::new())],
            false,
        ),
    );
    config.port_configurations.insert(
        TLS_PORT,
        PortConfiguration::new(
            vec![
                Box::new(TlsDiscriminatorFactory::new()),
                Box::new(HttpRequestDiscriminatorFactory::new()),
            ],
            false,
        ),
    );
}

// All initialization that doesn't specifically require lack of privilege should be done here.
pub fn privileged_parse_args(
    dirs_wrapper: &dyn DirsWrapper,
    multi_config: &MultiConfig,
    privileged_config: &mut BootstrapperConfig,
) -> Result<(), ConfiguratorError> {
    let (real_user, data_directory_path, chain) =
        real_user_data_directory_path_and_chain(dirs_wrapper, multi_config);
    let directory = match data_directory_path {
        Some(data_directory_path) => data_directory_path,
        None => data_directory_from_context(dirs_wrapper, &real_user, chain),
    };
    privileged_config.real_user = real_user;
    privileged_config.data_directory = directory;
    privileged_config.blockchain_bridge_config.chain = chain;

    let dns_servers_opt = value_m!(multi_config, "dns-servers", IpAddrs)
        .map(|ip_addrs| ip_addrs.ips.iter().map(|ip| SocketAddr::new(*ip, 53)).collect_vec());
    privileged_config.dns_servers = dns_servers_opt
        .unwrap_or_else(|| vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)]);

    privileged_config.log_level =
        value_m!(multi_config, "log-level", LevelFilter).unwrap_or(LevelFilter::Warn);

    privileged_config.ui_gateway_config.ui_port =
        value_m!(multi_config, "ui-port", InsecurePort)
            .map(|insecure_port| insecure_port.port)
            .unwrap_or(DEFAULT_UI_PORT);

    privileged_config.crash_point =
        value_m!(multi_config, "crash-point", CrashPoint).unwrap_or(CrashPoint::None);

    if let Some(public_key_str) = value_m!(multi_config, "fake-public-key", String) {
        let (main_public_key, alias_public_key) =
            match BASE64_STANDARD_NO_PAD.decode(&public_key_str) {
                Ok(mut key) => {
                    let main_public_key = PublicKey::new(&key);
                    key.reverse();
                    let alias_public_key = PublicKey::new(&key);
                    (main_public_key, alias_public_key)
                }
                Err(e) => panic!("Invalid fake public key: {} ({:?})", public_key_str, e),
            };
        let main_cryptde_null = CryptDENull::from(
            &main_public_key,
            privileged_config.blockchain_bridge_config.chain,
        );
        let alias_cryptde_null = CryptDENull::from(
            &alias_public_key,
            privileged_config.blockchain_bridge_config.chain,
        );
        privileged_config.main_cryptde_null_opt = Some(main_cryptde_null);
        privileged_config.alias_cryptde_null_opt = Some(alias_cryptde_null);
    }
    Ok(())
}

fn configure_database(
    config: &BootstrapperConfig,
    persistent_config: &mut dyn PersistentConfiguration,
) -> Result<(), ConfiguratorError> {
    // We don't want to panic in case clandestine_port or blockchain_service_url is not configured
    // inside the bootstrap config
    if let Some(port) = config.clandestine_port_opt {
        if let Err(pce) = persistent_config.set_clandestine_port(port) {
            return Err(pce.into_configurator_error("clandestine-port"));
        }
    }
    let schema_neighborhood_mode: SchemaNeighborhoodMode = (&config.neighborhood_config.mode).into();
    if let Err(pce) = persistent_config.set_neighborhood_mode(schema_neighborhood_mode) {
        return Err(pce.into_configurator_error("neighborhood-mode"));
    }
    if let Err(pce) = persistent_config.set_min_hops(config.neighborhood_config.min_hops) {
        return Err(pce.into_configurator_error("min-hops"));
    }
    if let Some(url) = config
        .blockchain_bridge_config
        .blockchain_service_url_opt
        .as_ref()
    {
        if let Err(pce) = persistent_config.set_blockchain_service_url(url) {
            return Err(pce.into_configurator_error("blockchain-service-url"));
        }
    }
    if let Err(pce) = persistent_config.set_gas_price(config.blockchain_bridge_config.gas_price) {
        return Err(pce.into_configurator_error("gas-price"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::bootstrapper::{BootstrapperConfig, RealUser};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::db_config::config_dao::ConfigDaoReal;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::db_config::persistent_configuration::PersistentConfigurationReal;
    use crate::node_configurator::unprivileged_parse_args_configuration::UnprivilegedParseArgsConfigurationDaoNull;
    use crate::node_test_utils::DirsWrapperMock;
    use crate::sub_lib::cryptde::CryptDE;
    use crate::sub_lib::neighborhood::NeighborhoodMode::ZeroHop;
    use crate::sub_lib::neighborhood::{
        Hops, NeighborhoodConfig, NeighborhoodMode, NodeDescriptor,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::unshared_test_utils::{
        make_pre_populated_mocked_directory_wrapper, make_simplified_multi_config,
    };
    use crate::test_utils::{assert_string_contains, main_cryptde, ArgsBuilder};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::multi_config::VirtualCommandLine;
    use masq_lib::test_utils::environment_guard::{ClapGuard, EnvironmentGuard};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::{running_test, slice_of_strs_to_vec_of_strings};
    use rustc_hex::FromHex;
    use std::convert::TryFrom;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::vec;

    #[test]
    fn node_configurator_standard_unprivileged_uses_parse_args_configurator_dao_real() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "node_configurator_standard_unprivileged_uses_parse_args_configurator_dao_real",
        );
        let neighbor = vec![NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-mainnet:MTEyMjMzNDQ1NTY2Nzc4ODExMjIzMzQ0NTU2Njc3ODg@1.2.3.4:1234",
        ))
        .unwrap()];
        {
            let conn = DbInitializerReal::default()
                .initialize(home_dir.as_path(), DbInitializationConfig::test_default())
                .unwrap();
            let mut persistent_config = PersistentConfigurationReal::from(conn);
            persistent_config.change_password(None, "password").unwrap();
            persistent_config
                .set_past_neighbors(Some(neighbor.clone()), "password")
                .unwrap();
        }
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-mainnet",
            "--db-password",
            "password",
            "--neighborhood-mode",
            "originate-only",
        ]);
        let mut privileged_config = BootstrapperConfig::default();
        privileged_config.data_directory = home_dir;
        let subject = NodeConfiguratorStandardUnprivileged {
            privileged_config,
            logger: Logger::new("test"),
        };

        let result = subject.configure(&multi_config).unwrap();

        let set_neighbors = if let NeighborhoodMode::OriginateOnly(neighbors, _) =
            result.neighborhood_config.mode
        {
            neighbors
        } else {
            panic!(
                "we expected originate only mode but got: {:?}",
                result.neighborhood_config.mode
            )
        };
        assert_eq!(set_neighbors, neighbor)
    }

    #[test]
    fn configure_database_handles_error_during_setting_clandestine_port() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1000);
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_clandestine_port_result(Err(PersistentConfigError::TransactionError));

        let result = configure_database(&config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::TransactionError.into_configurator_error("clandestine-port"))
        )
    }

    #[test]
    fn configure_database_handles_error_during_setting_gas_price() {
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = None;
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_neighborhood_mode_result(Ok(()))
            .set_min_hops_result(Ok(()))
            .set_gas_price_result(Err(PersistentConfigError::TransactionError));

        let result = configure_database(&config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::TransactionError.into_configurator_error("gas-price"))
        )
    }

    #[test]
    fn configure_database_handles_error_during_setting_blockchain_service_url() {
        let mut config = BootstrapperConfig::new();
        config.blockchain_bridge_config.blockchain_service_url_opt =
            Some("https://infura.io/ID".to_string());
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_neighborhood_mode_result(Ok(()))
            .set_min_hops_result(Ok(()))
            .set_blockchain_service_url_result(Err(PersistentConfigError::TransactionError));

        let result = configure_database(&config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::TransactionError
                .into_configurator_error("blockchain-service-url"))
        )
    }

    #[test]
    fn configure_database_handles_error_during_setting_neighborhood_mode() {
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config.mode = ZeroHop;
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_neighborhood_mode_result(Err(PersistentConfigError::TransactionError));

        let result = configure_database(&config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::TransactionError
                .into_configurator_error("neighborhood-mode"))
        )
    }

    #[test]
    fn configure_database_handles_error_during_setting_min_hops() {
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config.min_hops = Hops::FourHops;
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_neighborhood_mode_result(Ok(()))
            .set_min_hops_result(Err(PersistentConfigError::TransactionError));

        let result = configure_database(&config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::TransactionError.into_configurator_error("min-hops"))
        )
    }

    fn make_default_cli_params() -> ArgsBuilder {
        ArgsBuilder::new().param("--ip", "1.2.3.4")
    }

    #[test]
    fn server_initializer_collected_params_can_read_parameters_from_config_file() {
        running_test();
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "server_initializer_collected_params_can_read_parameters_from_config_file",
        );
        {
            let mut config_file = File::create(home_dir.join("config.toml")).unwrap();
            config_file
                .write_all(b"dns-servers = \"111.111.111.111,222.222.222.222\"\n")
                .unwrap();
        }
        let directory_wrapper = make_pre_populated_mocked_directory_wrapper();

        let gathered_params = server_initializer_collected_params(
            &directory_wrapper,
            &slice_of_strs_to_vec_of_strings(&["", "--data-directory", home_dir.to_str().unwrap()]),
        )
        .unwrap();

        let multi_config = gathered_params.multi_config;
        assert_eq!(
            value_m!(multi_config, "dns-servers", String).unwrap(),
            "111.111.111.111,222.222.222.222".to_string()
        );
    }

    #[test]
    fn can_read_dns_servers_and_consuming_private_key_from_config_file() {
        running_test();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "can_read_wallet_parameters_from_config_file",
        );
        let mut persistent_config = PersistentConfigurationReal::new(Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir.clone(), DbInitializationConfig::test_default())
                .unwrap(),
        )));
        let consuming_private_key =
            "89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF";
        let config_file_path = home_dir.join("config.toml");
        {
            let mut config_file = File::create(&config_file_path).unwrap();
            writeln!(
                config_file,
                "consuming-private-key = \"{}\"",
                consuming_private_key
            )
            .unwrap();
        }
        let args = ArgsBuilder::new()
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--ip", "1.2.3.4");
        let mut bootstrapper_config = BootstrapperConfig::new();
        let multi_config = make_new_multi_config(
            &app_node(),
            vec![
                Box::new(CommandLineVcl::new(args.into())),
                Box::new(ConfigFileVcl::new(&config_file_path, false).unwrap()),
            ],
        )
        .unwrap();

        privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut bootstrapper_config)
            .unwrap();
        let node_parse_args_configurator = UnprivilegedParseArgsConfigurationDaoNull {};
        node_parse_args_configurator
            .unprivileged_parse_args(
                &multi_config,
                &mut bootstrapper_config,
                &mut persistent_config,
                &Logger::new("test logger"),
            )
            .unwrap();

        let consuming_private_key_bytes: Vec<u8> = consuming_private_key.from_hex().unwrap();
        let consuming_keypair =
            Bip32EncryptionKeyProvider::from_raw_secret(consuming_private_key_bytes.as_ref())
                .unwrap();
        assert_eq!(
            bootstrapper_config.consuming_wallet_opt,
            Some(Wallet::from(consuming_keypair)),
        );
        let public_key = PublicKey::new(&[1, 2, 3]);
        let payer = bootstrapper_config
            .consuming_wallet_opt
            .unwrap()
            .as_payer(&public_key, &TEST_DEFAULT_CHAIN.rec().contract);
        let cryptdenull = CryptDENull::from(&public_key, TEST_DEFAULT_CHAIN);
        assert!(
            payer.owns_secret_key(&cryptdenull.digest()),
            "Neighborhood config should have a WalletKind::KeyPair wallet"
        );
    }

    #[test]
    fn privileged_parse_args_creates_configurations() {
        running_test();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "privileged_parse_args_creates_configurations",
        );
        let args = ArgsBuilder::new()
            .param("--config-file", "specified_config.toml")
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param(
                "--neighbors",
                "QmlsbA:1.2.3.4:1234;2345,VGVk:2.3.4.5:3456;4567",
            )
            .param("--ip", "34.56.78.90")
            .param("--clandestine-port", "1234")
            .param("--ui-port", "5335")
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--blockchain-service-url", "http://127.0.0.1:8545")
            .param("--log-level", "trace")
            .param("--fake-public-key", "AQIDBA")
            .param("--db-password", "secret-db-password")
            .param(
                "--earning-wallet",
                "0x0123456789012345678901234567890123456789",
            )
            .param(
                "--consuming-private-key",
                "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01",
            )
            .param("--real-user", "999:999:/home/booga")
            .param("--chain", "polygon-mumbai");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();

        privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        assert_eq!(
            value_m!(multi_config, "config-file", PathBuf),
            Some(PathBuf::from("specified_config.toml")),
        );
        assert_eq!(
            config.dns_servers,
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            ),
        );
        assert_eq!(config.ui_gateway_config.ui_port, 5335);
        assert_eq!(
            config.neighborhood_config,
            NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop, // not populated on the privileged side
                min_hops: Hops::ThreeHops,
            }
        );
        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url_opt,
            None,
        );
        assert_eq!(config.data_directory, home_dir);
        assert_eq!(
            config.main_cryptde_null_opt.unwrap().public_key(),
            &PublicKey::new(&[1, 2, 3, 4]),
        );
        assert_eq!(
            config.real_user,
            RealUser::new(Some(999), Some(999), Some(PathBuf::from("/home/booga")))
        );
    }

    #[test]
    fn privileged_parse_args_creates_configuration_with_defaults() {
        running_test();
        let args = ArgsBuilder::new().param("--ip", "1.2.3.4");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();

        privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config-file", PathBuf)
        );
        assert_eq!(
            config.dns_servers,
            vec!(SocketAddr::from_str("1.1.1.1:53").unwrap())
        );
        assert_eq!(config.crash_point, CrashPoint::None);
        assert_eq!(config.ui_gateway_config.ui_port, DEFAULT_UI_PORT);
        assert!(config.main_cryptde_null_opt.is_none());
        assert_eq!(
            config.real_user,
            RealUser::new(None, None, None).populate(&DirsWrapperReal {})
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn privileged_parse_args_with_real_user_defaults_data_directory_properly() {
        running_test();
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--real-user", "::/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();

        privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        #[cfg(target_os = "linux")]
        assert_eq!(
            config.data_directory,
            PathBuf::from("/home/booga/.local/share/MASQ")
                .join(DEFAULT_CHAIN.rec().literal_identifier)
        );

        #[cfg(target_os = "macos")]
        assert_eq!(
            config.data_directory,
            PathBuf::from("/home/booga/Library/Application Support/MASQ")
                .join(DEFAULT_CHAIN.rec().literal_identifier)
        );
    }

    #[test]
    fn privileged_parse_args_with_no_command_line_params() {
        running_test();
        let args = ArgsBuilder::new();
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_node(), vcls).unwrap();

        privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config-file", PathBuf)
        );
        assert_eq!(
            config.dns_servers,
            vec!(SocketAddr::from_str("1.1.1.1:53").unwrap())
        );
        assert_eq!(config.crash_point, CrashPoint::None);
        assert_eq!(config.ui_gateway_config.ui_port, DEFAULT_UI_PORT);
        assert!(config.main_cryptde_null_opt.is_none());
        assert_eq!(
            config.real_user,
            RealUser::new(None, None, None).populate(&DirsWrapperReal {})
        );
    }

    #[test]
    fn no_parameters_produces_configuration_for_crash_point() {
        running_test();
        let args = make_default_cli_params();
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_multi_config(&app_node(), vec![vcl]).unwrap();

        privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        assert_eq!(config.crash_point, CrashPoint::None);
    }

    #[test]
    fn with_parameters_produces_configuration_for_crash_point() {
        running_test();
        let args = make_default_cli_params().param("--crash-point", "panic");
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_multi_config(&app_node(), vec![vcl]).unwrap();

        privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        assert_eq!(config.crash_point, CrashPoint::Panic);
    }

    #[test]
    fn server_initializer_collected_params_senses_when_user_specifies_config_file() {
        running_test();
        let home_dir = PathBuf::from("/unexisting_home/unexisting_alice");
        let data_dir = home_dir.join("data_dir");
        let args = ArgsBuilder::new()
            .param("--config-file", "booga.toml") // nonexistent config file: should return error because user-specified
            .param("--chain", "polygon-mainnet");
        let args_vec: Vec<String> = args.into();
        let dir_wrapper = DirsWrapperMock::new()
            .home_dir_result(Some(home_dir))
            .data_dir_result(Some(data_dir));
        let result = server_initializer_collected_params(&dir_wrapper, args_vec.as_slice()).err();

        match result {
            None => panic!("Expected a value, got None"),
            Some(mut error) => {
                assert_eq!(error.param_errors.len(), 1);
                let param_error = error.param_errors.remove(0);
                assert_eq!(param_error.parameter, "config-file".to_string());
                assert_string_contains(&param_error.reason, "Couldn't open configuration file ");
                assert_string_contains(&param_error.reason, ". Are you sure it exists?");
            }
        }
    }

    #[test]
    fn privileged_configuration_accepts_network_chain_selection_for_multinode() {
        running_test();
        let _clap_guard = ClapGuard::new();
        let subject = NodeConfiguratorStandardPrivileged::new();
        let args = ["--ip", "1.2.3.4", "--chain", "dev"];

        let config = subject
            .configure(&make_simplified_multi_config(args))
            .unwrap();

        assert_eq!(config.blockchain_bridge_config.chain, Chain::Dev);
    }

    #[test]
    fn privileged_configuration_accepts_network_chain_selection_for_ropsten() {
        running_test();
        let subject = NodeConfiguratorStandardPrivileged::new();
        let args = [
            "--ip",
            "1.2.3.4",
            "--chain",
            TEST_DEFAULT_CHAIN.rec().literal_identifier,
        ];

        let config = subject
            .configure(&make_simplified_multi_config(args))
            .unwrap();

        assert_eq!(config.blockchain_bridge_config.chain, TEST_DEFAULT_CHAIN);
    }

    #[test]
    fn privileged_configuration_defaults_network_chain_selection_to_mainnet() {
        running_test();
        let _clap_guard = ClapGuard::new();
        let subject = NodeConfiguratorStandardPrivileged::new();
        let args = ["--ip", "1.2.3.4"];

        let config = subject
            .configure(&make_simplified_multi_config(args))
            .unwrap();

        assert_eq!(
            config
                .blockchain_bridge_config
                .chain
                .rec()
                .literal_identifier,
            DEFAULT_CHAIN.rec().literal_identifier
        );
    }

    #[test]
    fn privileged_configuration_accepts_ropsten_network_chain_selection() {
        running_test();
        let subject = NodeConfiguratorStandardPrivileged::new();
        let args = [
            "--ip",
            "1.2.3.4",
            "--chain",
            TEST_DEFAULT_CHAIN.rec().literal_identifier,
        ];

        let bootstrapper_config = subject
            .configure(&make_simplified_multi_config(args))
            .unwrap();
        assert_eq!(
            bootstrapper_config.blockchain_bridge_config.chain,
            TEST_DEFAULT_CHAIN
        );
    }

    #[test]
    fn unprivileged_configuration_gets_parameter_gas_price() {
        running_test();
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "unprivileged_configuration_gets_parameter_gas_price",
        );
        let mut subject = NodeConfiguratorStandardUnprivileged::new(&BootstrapperConfig::new());
        subject.privileged_config = BootstrapperConfig::new();
        subject.privileged_config.data_directory = data_dir;
        let args = ["--ip", "1.2.3.4", "--gas-price", "57"];

        let config = subject
            .configure(&make_simplified_multi_config(args))
            .unwrap();

        assert_eq!(config.blockchain_bridge_config.gas_price, 57);
    }

    #[test]
    fn unprivileged_configuration_sets_default_gas_price_when_not_provided() {
        running_test();
        let _clap_guard = ClapGuard::new();
        let data_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "unprivileged_configuration_sets_default_gas_price_when_not_provided",
        );
        let mut subject = NodeConfiguratorStandardUnprivileged::new(&BootstrapperConfig::new());
        subject.privileged_config = BootstrapperConfig::new();
        subject.privileged_config.data_directory = data_dir;
        let args = ["--ip", "1.2.3.4"];

        let config = subject
            .configure(&make_simplified_multi_config(args))
            .unwrap();

        assert_eq!(config.blockchain_bridge_config.gas_price, 1);
    }

    #[test]
    fn server_initializer_collected_params_rejects_invalid_gas_price() {
        running_test();
        let _clap_guard = ClapGuard::new();
        let args = ArgsBuilder::new().param("--gas-price", "unleaded");
        let args_vec: Vec<String> = args.into();
        let dir_wrapper = make_pre_populated_mocked_directory_wrapper();

        let result = server_initializer_collected_params(&dir_wrapper, &args_vec.as_slice())
            .err()
            .unwrap();

        assert_eq!(
            result,
            ConfiguratorError::required("gas-price", "Invalid value: unleaded")
        )
    }

    #[test]
    fn configure_database_with_data_specified_on_command_line_and_in_database() {
        running_test();
        let mut config = BootstrapperConfig::new();
        let gas_price = 4u64;
        config.clandestine_port_opt = Some(1234);
        config.blockchain_bridge_config.gas_price = gas_price;
        config.neighborhood_config.mode =
            NeighborhoodMode::ConsumeOnly(vec![NodeDescriptor::try_from((
                main_cryptde(),
                format!(
                    "masq://{}:AQIDBA@1.2.3.4:1234/2345",
                    TEST_DEFAULT_CHAIN.rec().literal_identifier
                )
                .as_str(),
            ))
            .unwrap()]);
        config.neighborhood_config.min_hops = Hops::FourHops;
        config.blockchain_bridge_config.blockchain_service_url_opt =
            Some("https://infura.io/ID".to_string());
        let set_blockchain_service_params_arc = Arc::new(Mutex::new(vec![]));
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_gas_price_params_arc = Arc::new(Mutex::new(vec![]));
        let set_neighborhood_mode_params_arc = Arc::new(Mutex::new(vec![]));
        let set_min_hops_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_clandestine_port_result(Ok(()))
            .set_blockchain_service_url_params(&set_blockchain_service_params_arc)
            .set_blockchain_service_url_result(Ok(()))
            .set_neighborhood_mode_params(&set_neighborhood_mode_params_arc)
            .set_neighborhood_mode_result(Ok(()))
            .set_gas_price_params(&set_gas_price_params_arc)
            .set_gas_price_result(Ok(()))
            .set_min_hops_params(&set_min_hops_params_arc)
            .set_min_hops_result(Ok(()));

        let result = configure_database(&config, &mut persistent_config);

        assert_eq!(result, Ok(()));
        let set_blockchain_service_url = set_blockchain_service_params_arc.lock().unwrap();
        assert_eq!(
            *set_blockchain_service_url,
            vec!["https://infura.io/ID".to_string()]
        );
        let set_neighborhood_mode_params = set_neighborhood_mode_params_arc.lock().unwrap();
        assert_eq!(
            *set_neighborhood_mode_params,
            vec![SchemaNeighborhoodMode::ConsumeOnly]
        );
        let set_gas_price_params = set_gas_price_params_arc.lock().unwrap();
        assert_eq!(*set_gas_price_params, vec![gas_price]);
        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        assert_eq!(*set_clandestine_port_params, vec![1234]);
        let set_min_hops_params = set_min_hops_params_arc.lock().unwrap();
        assert_eq!(*set_min_hops_params, vec![Hops::FourHops])
    }

    #[test]
    fn configure_database_with_no_data_specified() {
        running_test();
        let config = BootstrapperConfig::new();
        let set_blockchain_service_params_arc = Arc::new(Mutex::new(vec![]));
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_neighborhood_mode_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = PersistentConfigurationMock::new()
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_blockchain_service_url_params(&set_blockchain_service_params_arc)
            .set_neighborhood_mode_params(&set_neighborhood_mode_params_arc)
            .set_neighborhood_mode_result(Ok(()))
            .set_min_hops_result(Ok(()))
            .set_gas_price_result(Ok(()));

        let result = configure_database(&config, &mut persistent_config);

        assert_eq!(result, Ok(()));
        let set_blockchain_service_url = set_blockchain_service_params_arc.lock().unwrap();
        let no_url: Vec<String> = vec![];
        assert_eq!(*set_blockchain_service_url, no_url);
        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        let no_ports: Vec<u16> = vec![];
        assert_eq!(*set_clandestine_port_params, no_ports);
        let neighborhood_mode_params = set_neighborhood_mode_params_arc.lock().unwrap();
        assert_eq!(
            *neighborhood_mode_params,
            vec![SchemaNeighborhoodMode::ZeroHop]
        )
    }

    #[test]
    fn external_data_is_properly_created_when_password_is_provided() {
        let mut configurator_standard =
            NodeConfiguratorStandardUnprivileged::new(&BootstrapperConfig::new());
        configurator_standard
            .privileged_config
            .blockchain_bridge_config
            .chain = DEFAULT_CHAIN;
        let multi_config = make_simplified_multi_config([
            "--neighborhood-mode",
            "zero-hop",
            "--db-password",
            "password",
        ]);

        let result = ExternalData::from((&configurator_standard, &multi_config));

        let expected = ExternalData::new(
            DEFAULT_CHAIN,
            SchemaNeighborhoodMode::ZeroHop,
            Some("password".to_string()),
        );
        assert_eq!(result, expected)
    }

    #[test]
    fn external_data_is_properly_created_when_no_password_is_provided() {
        let mut configurator_standard =
            NodeConfiguratorStandardUnprivileged::new(&BootstrapperConfig::new());
        configurator_standard
            .privileged_config
            .blockchain_bridge_config
            .chain = DEFAULT_CHAIN;
        let multi_config = make_simplified_multi_config(["--neighborhood-mode", "zero-hop"]);

        let result = ExternalData::from((&configurator_standard, &multi_config));

        let expected = ExternalData::new(DEFAULT_CHAIN, SchemaNeighborhoodMode::ZeroHop, None);
        assert_eq!(result, expected)
    }

    fn check_data_directory_combinations_when_user_specifies_data_directory_without_chain_specific_directory(
        chain_opt: Option<&str>,
        data_directory_opt: Option<&str>,
        expected: Option<&str>,
    ) {
        let home_dir = PathBuf::from("/home/cooga");
        let standard_data_dir = PathBuf::from("/home/cooga/.local");

        let args = match (chain_opt, data_directory_opt) {
            (Some(chain_opt), Some(data_directory_opt)) => ArgsBuilder::new()
                .param("--chain", chain_opt)
                .param("--real-user", "999:999:/home/cooga")
                .param("--data-directory", data_directory_opt),
            (None, Some(data_directory_opt)) => ArgsBuilder::new()
                .param("--data-directory", data_directory_opt)
                .param("--real-user", "999:999:/home/cooga"),
            (Some(chain_opt), None) => ArgsBuilder::new()
                .param("--chain", chain_opt)
                .param("--real-user", "999:999:/home/cooga"),
            (None, None) => ArgsBuilder::new().param("--real-user", "999:999:/home/cooga"),
        };
        let args_vec: Vec<String> = args.into();
        let dir_wrapper = match data_directory_opt {
            Some(data_directory_opt) => DirsWrapperMock::new()
                .home_dir_result(Some(home_dir))
                .data_dir_result(Some(PathBuf::from(data_directory_opt))),
            None => DirsWrapperMock::new()
                .home_dir_result(Some(home_dir))
                .data_dir_result(Some(PathBuf::from(standard_data_dir))),
        };

        let result = server_initializer_collected_params(&dir_wrapper, args_vec.as_slice())
            .unwrap()
            .data_directory
            .to_string_lossy()
            .to_string();

        assert_eq!(result, expected.unwrap());
    }

    #[test]
    fn server_initializer_collected_params_senses_when_user_specifies_data_directory_without_chain_specific_directory(
    ) {
        running_test();
        let home_dir = Path::new("/home/cooga");
        let home_dir_poly_main = home_dir.join(".local").join("MASQ").join("polygon-mainnet");
        let home_dir_poly_mumbai = home_dir.join(".local").join("MASQ").join("polygon-mumbai");
        vec![
            (None, None, Some(home_dir_poly_main.to_str().unwrap())),
            (
                Some("polygon-mumbai"),
                None,
                Some(home_dir_poly_mumbai.to_str().unwrap()),
            ),
            (None, Some("/cooga"), Some("/cooga")),
            (Some("polygon-mumbai"), Some("/cooga"), Some("/cooga")),
            (
                None,
                Some("/cooga/polygon-mumbai"),
                Some("/cooga/polygon-mumbai"),
            ),
            (
                None,
                Some("/cooga/polygon-mumbai/polygon-mainnet"),
                Some("/cooga/polygon-mumbai/polygon-mainnet"),
            ),
            (
                Some("polygon-mumbai"),
                Some("/cooga/polygon-mumbai"),
                Some("/cooga/polygon-mumbai"),
            ),
        ]
        .iter()
        .for_each(|(chain_opt, data_directory_opt, expected)| {
            check_data_directory_combinations_when_user_specifies_data_directory_without_chain_specific_directory(
                *chain_opt,
                *data_directory_opt,
                *expected
            );
        });
    }
}
