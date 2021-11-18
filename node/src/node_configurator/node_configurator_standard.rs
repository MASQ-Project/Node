// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::bootstrapper::BootstrapperConfig;
use crate::node_configurator::DirsWrapperReal;
use crate::node_configurator::{initialize_database, DirsWrapper, NodeConfigurator};
use masq_lib::crash_point::CrashPoint;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::ExpectValue;

pub struct NodeConfiguratorStandardPrivileged {
    dirs_wrapper: Box<dyn DirsWrapper>,
}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardPrivileged {
    fn configure(
        &self,
        multi_config: &MultiConfig,
    ) -> Result<BootstrapperConfig, ConfiguratorError> {
        let mut bootstrapper_config = BootstrapperConfig::new();
        standard::establish_port_configurations(&mut bootstrapper_config);
        standard::privileged_parse_args(
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
}

impl NodeConfigurator<BootstrapperConfig> for NodeConfiguratorStandardUnprivileged {
    fn configure(
        &self,
        multi_config: &MultiConfig,
    ) -> Result<BootstrapperConfig, ConfiguratorError> {
        let mut persistent_config = initialize_database(
            &self.privileged_config.data_directory,
            self.privileged_config.blockchain_bridge_config.chain,
        );
        let mut unprivileged_config = BootstrapperConfig::new();
        standard::unprivileged_parse_args(
            multi_config,
            &mut unprivileged_config,
            Some(persistent_config.as_mut()),
        )?;
        standard::configure_database(&unprivileged_config, persistent_config.as_mut())?;
        Ok(unprivileged_config)
    }
}

impl NodeConfiguratorStandardUnprivileged {
    pub fn new(privileged_config: &BootstrapperConfig) -> Self {
        Self {
            privileged_config: privileged_config.clone(),
        }
    }
}

pub mod standard {
    use super::*;
    use std::net::SocketAddr;
    use std::net::{IpAddr, Ipv4Addr};

    use clap::value_t;
    use log::LevelFilter;

    use crate::apps::app_node;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::bootstrapper::PortConfiguration;
    use crate::db_config::persistent_configuration::{
        PersistentConfigError, PersistentConfiguration,
    };
    use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
    use crate::node_configurator::{
        data_directory_from_context, determine_config_file_path,
        real_user_from_multi_config_or_populate, real_user_with_data_directory_opt_and_chain,
        DirsWrapper,
    };
    use crate::server_initializer::GatheredParams;
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::cryptde::CryptDE;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::cryptde_real::CryptDEReal;
    use crate::sub_lib::neighborhood::{
        NeighborhoodConfig, NeighborhoodMode, NodeDescriptor, DEFAULT_RATE_PACK,
    };
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::utils::make_new_multi_config;
    use crate::sub_lib::wallet::Wallet;
    use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
    use itertools::Itertools;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::{
        DEFAULT_CHAIN, DEFAULT_UI_PORT, HTTP_PORT, MASQ_URL_PREFIX, TLS_PORT,
    };
    use masq_lib::multi_config::{CommandLineVcl, ConfigFileVcl, EnvironmentVcl, MultiConfig};
    use masq_lib::shared_schema::{ConfiguratorError, ParamError};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::WrapResult;
    use rustc_hex::FromHex;
    use std::str::FromStr;

    pub fn server_initializer_collected_params<'a>(
        dirs_wrapper: &dyn DirsWrapper,
        args: &[String],
    ) -> Result<GatheredParams<'a>, ConfiguratorError> {
        let app = app_node();
        let (config_file_path, user_specified) =
            determine_config_file_path(dirs_wrapper, &app, args)?;
        let config_file_vcl = match ConfigFileVcl::new(&config_file_path, user_specified) {
            Ok(cfv) => Box::new(cfv),
            Err(e) => return Err(ConfiguratorError::required("config-file", &e.to_string())),
        };
        let multi_config = make_new_multi_config(
            &app,
            vec![
                Box::new(CommandLineVcl::new(args.to_vec())),
                Box::new(EnvironmentVcl::new(&app)),
                config_file_vcl,
            ],
        )?;
        let data_directory = config_file_path
            .parent()
            .map(|dir| dir.to_path_buf())
            .expectv("data_directory");
        let real_user = real_user_from_multi_config_or_populate(&multi_config, dirs_wrapper);
        GatheredParams::new(multi_config, data_directory, real_user).wrap_to_ok()
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

    pub fn privileged_parse_args(
        dirs_wrapper: &dyn DirsWrapper,
        multi_config: &MultiConfig,
        privileged_config: &mut BootstrapperConfig,
    ) -> Result<(), ConfiguratorError> {
        privileged_config
            .blockchain_bridge_config
            .blockchain_service_url_opt = value_m!(multi_config, "blockchain-service-url", String);

        let (real_user, data_directory_opt, chain) =
            real_user_with_data_directory_opt_and_chain(dirs_wrapper, multi_config);
        let directory =
            data_directory_from_context(dirs_wrapper, &real_user, &data_directory_opt, chain);
        privileged_config.real_user = real_user;
        privileged_config.data_directory = directory;
        privileged_config.blockchain_bridge_config.chain = chain;

        let joined_dns_servers_opt = value_m!(multi_config, "dns-servers", String);
        privileged_config.dns_servers = match joined_dns_servers_opt {
            Some(joined_dns_servers) => joined_dns_servers
                .split(',')
                .map(|ip_str| {
                    SocketAddr::new(
                        IpAddr::from_str(ip_str).expect("Bad clap validation for dns-servers"),
                        53,
                    )
                })
                .collect(),
            None => vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)],
        };

        privileged_config.log_level =
            value_m!(multi_config, "log-level", LevelFilter).unwrap_or(LevelFilter::Warn);

        privileged_config.ui_gateway_config.ui_port =
            value_m!(multi_config, "ui-port", u16).unwrap_or(DEFAULT_UI_PORT);

        privileged_config.crash_point =
            value_m!(multi_config, "crash-point", CrashPoint).unwrap_or(CrashPoint::None);

        if let Some(public_key_str) = value_m!(multi_config, "fake-public-key", String) {
            let (main_public_key, alias_public_key) = match base64::decode(&public_key_str) {
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

    pub fn unprivileged_parse_args(
        multi_config: &MultiConfig,
        unprivileged_config: &mut BootstrapperConfig,
        persistent_config_opt: Option<&mut dyn PersistentConfiguration>,
    ) -> Result<(), ConfiguratorError> {
        unprivileged_config.clandestine_port_opt = value_m!(multi_config, "clandestine-port", u16);
        let user_specified = multi_config.occurrences_of("gas-price") > 0;
        unprivileged_config.blockchain_bridge_config.gas_price = if user_specified {
            value_m!(multi_config, "gas-price", u64).expectv("gas price")
        } else {
            match persistent_config_opt {
                Some(ref persistent_config) => match persistent_config.gas_price() {
                    Ok(price) => price,
                    Err(pce) => return Err(pce.into_configurator_error("gas-price")),
                },
                None => 1,
            }
        };
        let mnc_result = if let Some(persistent_config) = persistent_config_opt {
            get_wallets(multi_config, persistent_config, unprivileged_config)?;
            make_neighborhood_config(multi_config, Some(persistent_config), unprivileged_config)
        } else {
            make_neighborhood_config(multi_config, None, unprivileged_config)
        };

        mnc_result.map(|config| unprivileged_config.neighborhood_config = config)
    }

    pub fn configure_database(
        config: &BootstrapperConfig,
        persistent_config: &mut (dyn PersistentConfiguration),
    ) -> Result<(), ConfiguratorError> {
        if let Some(port) = config.clandestine_port_opt {
            if let Err(pce) = persistent_config.set_clandestine_port(port) {
                return Err(pce.into_configurator_error("clandestine-port"));
            }
        }

        if let Err(pce) = persistent_config.set_gas_price(config.blockchain_bridge_config.gas_price)
        {
            return Err(pce.into_configurator_error("gas-price"));
        }
        Ok(())
    }

    pub fn get_wallets(
        multi_config: &MultiConfig,
        persistent_config: &mut dyn PersistentConfiguration,
        config: &mut BootstrapperConfig,
    ) -> Result<(), ConfiguratorError> {
        let mnemonic_seed_exists = match persistent_config.mnemonic_seed_exists() {
            Ok(flag) => flag,
            Err(pce) => return Err(pce.into_configurator_error("seed")),
        };
        validate_testing_parameters(mnemonic_seed_exists, multi_config)?;
        let earning_wallet_opt =
            standard::get_earning_wallet_from_address(multi_config, persistent_config)?;
        let mut consuming_wallet_opt =
            standard::get_consuming_wallet_from_private_key(multi_config)?;

        if (earning_wallet_opt.is_none() || consuming_wallet_opt.is_none()) && mnemonic_seed_exists
        {
            if let Some(db_password) =
                standard::get_db_password(multi_config, config, persistent_config)?
            {
                if consuming_wallet_opt.is_none() {
                    consuming_wallet_opt = standard::get_consuming_wallet_opt_from_derivation_path(
                        persistent_config,
                        &db_password,
                    )?;
                } else {
                    match persistent_config.consuming_wallet_derivation_path() {
                        Ok(Some(_)) => return Err(ConfiguratorError::required("consuming-private-key", "Cannot use when database contains mnemonic seed and consuming wallet derivation path")),
                        Ok(None) => (),
                        Err(pce) => return Err(pce.into_configurator_error("consuming-wallet")),
                    }
                }
            }
        }
        config.consuming_wallet = consuming_wallet_opt;
        config.earning_wallet = match earning_wallet_opt {
            Some(earning_wallet) => earning_wallet,
            None => DEFAULT_EARNING_WALLET.clone(),
        };
        Ok(())
    }

    fn validate_testing_parameters(
        mnemonic_seed_exists: bool,
        multi_config: &MultiConfig,
    ) -> Result<(), ConfiguratorError> {
        let consuming_wallet_specified =
            value_m!(multi_config, "consuming-private-key", String).is_some();
        let earning_wallet_specified = value_m!(multi_config, "earning-wallet", String).is_some();
        if mnemonic_seed_exists && (consuming_wallet_specified || earning_wallet_specified) {
            let parameter = match (consuming_wallet_specified, earning_wallet_specified) {
                (true, false) => "consuming-private-key",
                (false, true) => "earning-wallet",
                (true, true) => "consuming-private-key, earning-wallet",
                (false, false) => panic!("The if statement in Rust no longer works"),
            };
            Err(ConfiguratorError::required(parameter, "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information"))
        } else {
            Ok(())
        }
    }

    pub fn make_neighborhood_config(
        multi_config: &MultiConfig,
        persistent_config_opt: Option<&mut dyn PersistentConfiguration>,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<NeighborhoodConfig, ConfiguratorError> {
        let neighbor_configs: Vec<NodeDescriptor> = {
            match convert_ci_configs(multi_config)? {
                Some(configs) => configs,
                None => match persistent_config_opt {
                    Some(persistent_config) => {
                        get_past_neighbors(multi_config, persistent_config, unprivileged_config)?
                    }
                    None => vec![],
                },
            }
        };
        match make_neighborhood_mode(multi_config, neighbor_configs) {
            Ok(mode) => Ok(NeighborhoodConfig { mode }),
            Err(e) => Err(e),
        }
    }

    pub fn convert_ci_configs(
        multi_config: &MultiConfig,
    ) -> Result<Option<Vec<NodeDescriptor>>, ConfiguratorError> {
        type DescriptorParsingResult = Result<NodeDescriptor, ParamError>;
        match value_m!(multi_config, "neighbors", String) {
            None => Ok(None),
            Some(joined_configs) => {
                let separate_configs: Vec<String> = joined_configs
                    .split(',')
                    .map(|s| s.to_string())
                    .collect_vec();
                if separate_configs.is_empty() {
                    Ok(None)
                } else {
                    let dummy_cryptde: Box<dyn CryptDE> = {
                        if value_m!(multi_config, "fake-public-key", String).is_none() {
                            Box::new(CryptDEReal::new(TEST_DEFAULT_CHAIN))
                        } else {
                            Box::new(CryptDENull::new(TEST_DEFAULT_CHAIN))
                        }
                    };
                    let desired_chain = Chain::from(
                        value_m!(multi_config, "chain", String)
                            .unwrap_or_else(|| DEFAULT_CHAIN.rec().literal_identifier.to_string())
                            .as_str(),
                    );
                    let results = validate_descriptors_from_user(
                        separate_configs,
                        dummy_cryptde,
                        desired_chain,
                    );
                    let (ok, err): (Vec<DescriptorParsingResult>, Vec<DescriptorParsingResult>) =
                        results.into_iter().partition(|result| result.is_ok());
                    let ok = ok
                        .into_iter()
                        .map(|ok| ok.expect("NodeDescriptor"))
                        .collect_vec();
                    let err = err
                        .into_iter()
                        .map(|err| err.expect_err("ParamError"))
                        .collect_vec();
                    if err.is_empty() {
                        Ok(Some(ok))
                    } else {
                        Err(ConfiguratorError::new(err))
                    }
                }
            }
        }
    }

    fn validate_descriptors_from_user(
        descriptors: Vec<String>,
        dummy_cryptde: Box<dyn CryptDE>,
        desired_chain: Chain,
    ) -> Vec<Result<NodeDescriptor, ParamError>> {
        descriptors.into_iter()
            .map(
                |node_desc_from_ci| {
                    let node_desc_trimmed = node_desc_from_ci.trim();
                    match NodeDescriptor::try_from((dummy_cryptde.as_ref(), node_desc_trimmed)) {
                        Ok(descriptor) =>
                            {
                                let competence_from_descriptor = descriptor.blockchain;
                                if desired_chain == competence_from_descriptor {
                                    validate_mandatory_node_addr(node_desc_trimmed, descriptor)
                                } else {
                                    let name_of_desired_chain = desired_chain.rec().literal_identifier;
                                    Err(ParamError::new("neighbors", &format!("Mismatched chains. You are requiring access to '{}' ({}{}:<public key>@<node address>) with descriptor belonging to '{}'",
                                                                              name_of_desired_chain, MASQ_URL_PREFIX,
                                                                              name_of_desired_chain,
                                                                              competence_from_descriptor.rec().literal_identifier)))
                                }
                            }
                        Err(e) => ParamError::new("neighbors", &e).wrap_to_err()
                    }
                }
            )
            .collect_vec()
    }

    fn validate_mandatory_node_addr(
        supplied_descriptor: &str,
        descriptor: NodeDescriptor,
    ) -> Result<NodeDescriptor, ParamError> {
        if descriptor.node_addr_opt.is_some() {
            Ok(descriptor)
        } else {
            Err(ParamError::new(
                "neighbors",&format!("Neighbors supplied without ip addresses and ports are not valid: '{}<N/A>:<N/A>",
                                     if supplied_descriptor.ends_with("@:") { supplied_descriptor.strip_suffix(':').expect("logic failed")}
                                     else { supplied_descriptor }))
            )
        }
    }

    pub fn get_past_neighbors(
        multi_config: &MultiConfig,
        persistent_config: &mut dyn PersistentConfiguration,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<Vec<NodeDescriptor>, ConfiguratorError> {
        Ok(
            match &standard::get_db_password(multi_config, unprivileged_config, persistent_config)?
            {
                Some(db_password) => match persistent_config.past_neighbors(db_password) {
                    Ok(Some(past_neighbors)) => past_neighbors,
                    Ok(None) => vec![],
                    Err(PersistentConfigError::PasswordError) => {
                        return Err(ConfiguratorError::new(vec![ParamError::new(
                            "db-password",
                            "PasswordError",
                        )]))
                    }
                    Err(e) => {
                        return Err(ConfiguratorError::new(vec![ParamError::new(
                            "[past neighbors]",
                            &format!("{:?}", e),
                        )]))
                    }
                },
                None => vec![],
            },
        )
    }

    fn make_neighborhood_mode(
        multi_config: &MultiConfig,
        neighbor_configs: Vec<NodeDescriptor>,
    ) -> Result<NeighborhoodMode, ConfiguratorError> {
        let neighborhood_mode_opt = value_m!(multi_config, "neighborhood-mode", String);
        match neighborhood_mode_opt {
            Some(ref s) if s == "standard" => {
                neighborhood_mode_standard(multi_config, neighbor_configs)
            }
            Some(ref s) if s == "originate-only" => {
                if neighbor_configs.is_empty() {
                    Err(ConfiguratorError::required("neighborhood-mode", "Node cannot run as --neighborhood-mode originate-only without --neighbors specified"))
                } else {
                    Ok(NeighborhoodMode::OriginateOnly(
                        neighbor_configs,
                        DEFAULT_RATE_PACK,
                    ))
                }
            }
            Some(ref s) if s == "consume-only" => {
                let mut errors = ConfiguratorError::new(vec![]);
                if neighbor_configs.is_empty() {
                    errors = errors.another_required("neighborhood-mode", "Node cannot run as --neighborhood-mode consume-only without --neighbors specified");
                }
                if value_m!(multi_config, "dns-servers", String).is_some() {
                    errors = errors.another_required("neighborhood-mode", "Node cannot run as --neighborhood-mode consume-only if --dns-servers is specified");
                }
                if !errors.is_empty() {
                    Err(errors)
                } else {
                    Ok(NeighborhoodMode::ConsumeOnly(neighbor_configs))
                }
            }
            Some(ref s) if s == "zero-hop" => {
                if !neighbor_configs.is_empty() {
                    Err(ConfiguratorError::required("neighborhood-mode", "Node cannot run as --neighborhood-mode zero-hop if --neighbors is specified"))
                } else if value_m!(multi_config, "ip", IpAddr).is_some() {
                    Err(ConfiguratorError::required(
                        "neighborhood-mode",
                        "Node cannot run as --neighborhood-mode zero-hop if --ip is specified",
                    ))
                } else {
                    Ok(NeighborhoodMode::ZeroHop)
                }
            }
            // These two cases are untestable
            Some(ref s) => panic!(
                "--neighborhood-mode {} has not been properly provided for in the code",
                s
            ),
            None => neighborhood_mode_standard(multi_config, neighbor_configs),
        }
    }

    fn neighborhood_mode_standard(
        multi_config: &MultiConfig,
        neighbor_configs: Vec<NodeDescriptor>,
    ) -> Result<NeighborhoodMode, ConfiguratorError> {
        let ip = match value_m!(multi_config, "ip", IpAddr) {
            Some(ip) => ip,
            None => {
                return Err(ConfiguratorError::required(
                    "neighborhood-mode",
                    "Node cannot run as --neighborhood-mode standard without --ip specified",
                ))
            }
        };
        Ok(NeighborhoodMode::Standard(
            NodeAddr::new(&ip, &[]),
            neighbor_configs,
            DEFAULT_RATE_PACK,
        ))
    }

    fn get_earning_wallet_from_address(
        multi_config: &MultiConfig,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<Option<Wallet>, ConfiguratorError> {
        let earning_wallet_from_command_line_opt = value_m!(multi_config, "earning-wallet", String);
        let earning_wallet_from_database_opt = match persistent_config.earning_wallet_from_address()
        {
            Ok(ewfdo) => ewfdo,
            Err(e) => return Err(e.into_configurator_error("earning-wallet")),
        };
        match (
            earning_wallet_from_command_line_opt,
            earning_wallet_from_database_opt,
        ) {
            (None, None) => Ok(None),
            (Some(address), None) => Ok(Some(
                Wallet::from_str(&address)
                    .expect("--earning-wallet not properly constrained by clap"),
            )),
            (None, Some(wallet)) => Ok(Some(wallet)),
            (Some(address), Some(wallet)) => {
                if wallet.to_string().to_lowercase() == address.to_lowercase() {
                    Ok(Some(wallet))
                } else {
                    Err(ConfiguratorError::required(
                        "earning-wallet",
                        &format!("Cannot change to an address ({}) different from that previously set ({})", address.to_lowercase(), wallet.to_string().to_lowercase())
                    ))
                }
            }
        }
    }

    fn get_consuming_wallet_opt_from_derivation_path(
        persistent_config: &dyn PersistentConfiguration,
        db_password: &str,
    ) -> Result<Option<Wallet>, ConfiguratorError> {
        match persistent_config.consuming_wallet_derivation_path() {
            Ok(None) => Ok(None),
            Ok(Some(derivation_path)) => match persistent_config.mnemonic_seed(db_password) {
                Ok(None) => Ok(None),
                Ok(Some(mnemonic_seed)) => {
                    let keypair =
                        Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), &derivation_path)
                            .unwrap_or_else(|_| {
                                panic!(
                            "Error making keypair from mnemonic seed and derivation path {}",
                            derivation_path
                        )
                            });
                    Ok(Some(Wallet::from(keypair)))
                }
                Err(e) => match e {
                    PersistentConfigError::PasswordError => Err(ConfiguratorError::required(
                        "db-password",
                        "Incorrect password for retrieving mnemonic seed",
                    )),
                    e => panic!("{:?}", e),
                },
            },
            Err(e) => Err(e.into_configurator_error("consuming-private-key")),
        }
    }

    fn get_consuming_wallet_from_private_key(
        multi_config: &MultiConfig,
    ) -> Result<Option<Wallet>, ConfiguratorError> {
        match value_m!(multi_config, "consuming-private-key", String) {
            Some(consuming_private_key_string) => {
                match consuming_private_key_string.from_hex::<Vec<u8>>() {
                    Ok(raw_secret) => match Bip32ECKeyPair::from_raw_secret(&raw_secret[..]) {
                        Ok(keypair) => Ok(Some(Wallet::from(keypair))),
                        Err(e) => panic!(
                            "Internal error: bad clap validation for consuming-private-key: {:?}",
                            e
                        ),
                    },
                    Err(e) => panic!(
                        "Internal error: bad clap validation for consuming-private-key: {:?}",
                        e
                    ),
                }
            }
            None => Ok(None),
        }
    }

    pub fn get_db_password(
        multi_config: &MultiConfig,
        config: &mut BootstrapperConfig,
        persistent_config: &mut dyn PersistentConfiguration,
    ) -> Result<Option<String>, ConfiguratorError> {
        if let Some(db_password) = &config.db_password_opt {
            return Ok(Some(db_password.clone()));
        }
        let db_password_opt = value_m!(multi_config, "db-password", String);
        if let Some(db_password) = &db_password_opt {
            set_db_password_at_first_mention(db_password, persistent_config)?;
            config.db_password_opt = Some(db_password.clone());
        };
        Ok(db_password_opt)
    }

    fn set_db_password_at_first_mention(
        db_password: &str,
        persistent_config: &mut dyn PersistentConfiguration,
    ) -> Result<bool, ConfiguratorError> {
        match persistent_config.check_password(None) {
            Ok(true) => match persistent_config.change_password(None, db_password) {
                Ok(_) => Ok(true),
                Err(e) => Err(e.into_configurator_error("db-password")),
            },
            Ok(false) => Ok(false),
            Err(e) => Err(e.into_configurator_error("db-password")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::db_config::persistent_configuration::PersistentConfigError;
        use crate::db_config::persistent_configuration::PersistentConfigError::NotPresent;
        use crate::sub_lib::utils::make_new_test_multi_config;
        use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
        use crate::test_utils::pure_test_utils::{
            make_default_persistent_configuration, make_simplified_multi_config,
        };
        use crate::test_utils::ArgsBuilder;
        use masq_lib::constants::DEFAULT_CHAIN;
        use masq_lib::multi_config::VirtualCommandLine;
        use masq_lib::utils::running_test;
        use std::sync::{Arc, Mutex};

        #[test]
        fn get_wallets_handles_consuming_private_key_and_earning_wallet_address_when_database_contains_mnemonic_seed(
        ) {
            running_test();
            let args = ArgsBuilder::new()
                .param(
                    "--consuming-private-key",
                    "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
                )
                .param(
                    "--earning-wallet",
                    "0x0123456789012345678901234567890123456789",
                )
                .param("--db-password", "booga");
            let vcls: Vec<Box<dyn VirtualCommandLine>> =
                vec![Box::new(CommandLineVcl::new(args.into()))];
            let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
            let mut persistent_config = PersistentConfigurationMock::new()
                .earning_wallet_from_address_result(Ok(None))
                .mnemonic_seed_exists_result(Ok(true));
            let mut bootstrapper_config = BootstrapperConfig::new();

            let result = standard::get_wallets(
                &multi_config,
                &mut persistent_config,
                &mut bootstrapper_config,
            )
            .err()
            .unwrap();

            assert_eq! (result, ConfiguratorError::required("consuming-private-key, earning-wallet", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information"))
        }

        #[test]
        fn get_wallets_handles_consuming_private_key_with_mnemonic_seed() {
            running_test();
            let args = ArgsBuilder::new()
                .param(
                    "--consuming-private-key",
                    "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
                )
                .param("--db-password", "booga");
            let vcls: Vec<Box<dyn VirtualCommandLine>> =
                vec![Box::new(CommandLineVcl::new(args.into()))];
            let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
            let mut persistent_config = PersistentConfigurationMock::new()
                .earning_wallet_from_address_result(Ok(None))
                .check_password_result(Ok(false))
                .mnemonic_seed_exists_result(Ok(true));
            let mut bootstrapper_config = BootstrapperConfig::new();

            let result = standard::get_wallets(
                &multi_config,
                &mut persistent_config,
                &mut bootstrapper_config,
            )
            .err()
            .unwrap();

            assert_eq! (result, ConfiguratorError::required("consuming-private-key", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information"))
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
                Err(PersistentConfigError::TransactionError
                    .into_configurator_error("clandestine-port"))
            )
        }

        #[test]
        fn configure_database_handles_error_during_setting_gas_price() {
            let mut config = BootstrapperConfig::new();
            config.clandestine_port_opt = None;
            let mut persistent_config = PersistentConfigurationMock::new()
                .earning_wallet_address_result(Ok(Some(
                    "0x0123456789012345678901234567890123456789".to_string(),
                )))
                .set_gas_price_result(Err(PersistentConfigError::TransactionError));

            let result = configure_database(&config, &mut persistent_config);

            assert_eq!(
                result,
                Err(PersistentConfigError::TransactionError.into_configurator_error("gas-price"))
            )
        }

        #[test]
        fn get_earning_wallet_from_address_handles_error_retrieving_earning_wallet_from_address() {
            let args = ArgsBuilder::new().param(
                "--earning-wallet",
                "0x0123456789012345678901234567890123456789",
            );
            let vcls: Vec<Box<dyn VirtualCommandLine>> =
                vec![Box::new(CommandLineVcl::new(args.into()))];
            let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
            let persistent_config = PersistentConfigurationMock::new()
                .earning_wallet_from_address_result(Err(PersistentConfigError::NotPresent));

            let result = get_earning_wallet_from_address(&multi_config, &persistent_config);

            assert_eq!(
                result,
                Err(PersistentConfigError::NotPresent.into_configurator_error("earning-wallet"))
            );
        }

        #[test]
        fn get_consuming_wallet_opt_from_derivation_path_handles_error_retrieving_consuming_wallet_derivation_path(
        ) {
            let persistent_config = PersistentConfigurationMock::new()
                .consuming_wallet_derivation_path_result(Err(PersistentConfigError::Collision(
                    "irrelevant".to_string(),
                )));

            let result =
                get_consuming_wallet_opt_from_derivation_path(&persistent_config, "irrelevant");

            assert_eq!(
                result,
                Err(ConfiguratorError::new(vec![ParamError::new(
                    "consuming-private-key",
                    &format!(
                        "{:?}",
                        PersistentConfigError::Collision("irrelevant".to_string())
                    )
                ),]))
            )
        }

        #[test]
        fn convert_ci_configs_handles_blockchain_mismatch() {
            let multi_config = make_simplified_multi_config([
                "MASQNode",
                "--neighbors",
                "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@12.23.34.45:5678",
                "--chain",
                DEFAULT_CHAIN.rec().literal_identifier,
            ]);

            let result = standard::convert_ci_configs(&multi_config).err().unwrap();

            assert_eq!(
                result,
                ConfiguratorError::required(
                    "neighbors",
                    "Mismatched chains. You are requiring access to 'eth-mainnet' (masq://eth-mainnet:<public key>@<node address>) with descriptor belonging to 'eth-ropsten'"
                )
            )
        }

        #[test]
        fn get_earning_wallet_from_address_handles_attempted_wallet_change() {
            running_test();
            let args = ArgsBuilder::new().param(
                "--earning-wallet",
                "0x0123456789012345678901234567890123456789",
            );
            let vcls: Vec<Box<dyn VirtualCommandLine>> =
                vec![Box::new(CommandLineVcl::new(args.into()))];
            let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
            let persistent_config = PersistentConfigurationMock::new()
                .earning_wallet_from_address_result(Ok(Some(Wallet::new(
                    "0x9876543210987654321098765432109876543210",
                ))));

            let result =
                standard::get_earning_wallet_from_address(&multi_config, &persistent_config)
                    .err()
                    .unwrap();

            assert_eq! (result, ConfiguratorError::required("earning-wallet", "Cannot change to an address (0x0123456789012345678901234567890123456789) different from that previously set (0x9876543210987654321098765432109876543210)"))
        }

        #[test]
        fn get_consuming_wallet_opt_from_derivation_path_handles_bad_password() {
            running_test();
            let persistent_config = PersistentConfigurationMock::new()
                .consuming_wallet_derivation_path_result(Ok(Some("m/44'/60'/1'/2/3".to_string())))
                .mnemonic_seed_result(Err(PersistentConfigError::PasswordError));

            let result = standard::get_consuming_wallet_opt_from_derivation_path(
                &persistent_config,
                "bad password",
            )
            .err()
            .unwrap();

            assert_eq!(
                result,
                ConfiguratorError::required(
                    "db-password",
                    "Incorrect password for retrieving mnemonic seed"
                )
            )
        }

        #[test]
        fn set_db_password_at_first_mention_handles_existing_password() {
            let check_password_params_arc = Arc::new(Mutex::new(vec![]));
            let mut persistent_config = make_default_persistent_configuration()
                .check_password_params(&check_password_params_arc)
                .check_password_result(Ok(false));

            let result =
                standard::set_db_password_at_first_mention("password", &mut persistent_config);

            assert_eq!(result, Ok(false));
            let check_password_params = check_password_params_arc.lock().unwrap();
            assert_eq!(*check_password_params, vec![None])
        }

        #[test]
        fn set_db_password_at_first_mention_sets_password_correctly() {
            let change_password_params_arc = Arc::new(Mutex::new(vec![]));
            let mut persistent_config = make_default_persistent_configuration()
                .check_password_result(Ok(true))
                .change_password_params(&change_password_params_arc)
                .change_password_result(Ok(()));

            let result =
                standard::set_db_password_at_first_mention("password", &mut persistent_config);

            assert_eq!(result, Ok(true));
            let change_password_params = change_password_params_arc.lock().unwrap();
            assert_eq!(
                *change_password_params,
                vec![(None, "password".to_string())]
            )
        }

        #[test]
        fn set_db_password_at_first_mention_handles_password_check_error() {
            let check_password_params_arc = Arc::new(Mutex::new(vec![]));
            let mut persistent_config = make_default_persistent_configuration()
                .check_password_params(&check_password_params_arc)
                .check_password_result(Err(NotPresent));

            let result =
                standard::set_db_password_at_first_mention("password", &mut persistent_config);

            assert_eq!(
                result,
                Err(NotPresent.into_configurator_error("db-password"))
            );
            let check_password_params = check_password_params_arc.lock().unwrap();
            assert_eq!(*check_password_params, vec![None])
        }

        #[test]
        fn set_db_password_at_first_mention_handles_password_set_error() {
            let change_password_params_arc = Arc::new(Mutex::new(vec![]));
            let mut persistent_config = make_default_persistent_configuration()
                .check_password_result(Ok(true))
                .change_password_params(&change_password_params_arc)
                .change_password_result(Err(NotPresent));

            let result =
                standard::set_db_password_at_first_mention("password", &mut persistent_config);

            assert_eq!(
                result,
                Err(NotPresent.into_configurator_error("db-password"))
            );
            let change_password_params = change_password_params_arc.lock().unwrap();
            assert_eq!(
                *change_password_params,
                vec![(None, "password".to_string())]
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::app_node;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::bootstrapper::RealUser;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::db_config::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::db_config::persistent_configuration::PersistentConfigError::NotPresent;
    use crate::db_config::persistent_configuration::{
        PersistentConfigError, PersistentConfigurationReal,
    };
    use crate::node_configurator::node_configurator_standard::standard::server_initializer_collected_params;
    use crate::node_configurator::DirsWrapperReal;
    use crate::node_test_utils::DirsWrapperMock;
    use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
    use crate::sub_lib::cryptde::{CryptDE, PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::cryptde_real::CryptDEReal;
    use crate::sub_lib::neighborhood::{
        NeighborhoodConfig, NeighborhoodMode, NodeDescriptor, DEFAULT_RATE_PACK,
    };
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::utils::make_new_test_multi_config;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils;
    use crate::test_utils::pure_test_utils::{
        make_default_persistent_configuration, make_pre_populated_mocked_directory_wrapper,
        make_simplified_multi_config,
    };
    use crate::test_utils::{assert_string_contains, main_cryptde, ArgsBuilder};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::{DEFAULT_CHAIN, DEFAULT_GAS_PRICE, DEFAULT_UI_PORT};
    use masq_lib::multi_config::{
        CommandLineVcl, ConfigFileVcl, NameValueVclArg, VclArg, VirtualCommandLine,
    };
    use masq_lib::shared_schema::{ConfiguratorError, ParamError};
    use masq_lib::test_utils::environment_guard::{ClapGuard, EnvironmentGuard};
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::{running_test, SliceToVec};
    use rustc_hex::FromHex;
    use std::fs::File;
    use std::io::Write;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    fn make_default_cli_params() -> ArgsBuilder {
        ArgsBuilder::new().param("--ip", "1.2.3.4")
    }

    #[test]
    fn make_neighborhood_config_standard_happy_path() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .param("--ip", "1.2.3.4")
                    .param(
                        "--neighbors",
                        "masq://eth-mainnet:mhtjjdMt7Gyoebtb1yiK0hdaUx6j84noHdaAHeDR1S4@1.2.3.4:1234/2345,masq://eth-mainnet:Si06R3ulkOjJOLw1r2R9GOsY87yuinHU_IHK2FJyGnk@2.3.4.5:3456/4567",
                    )
                    .into(),
            ))]
        ).unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration()),
            &mut BootstrapperConfig::new(),
        );

        let dummy_cryptde = CryptDEReal::new(TEST_DEFAULT_CHAIN);
        assert_eq!(
            result,
            Ok(NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[]),
                    vec![
                        NodeDescriptor::try_from((
                            &dummy_cryptde as &dyn CryptDE,
                            "masq://eth-mainnet:mhtjjdMt7Gyoebtb1yiK0hdaUx6j84noHdaAHeDR1S4@1.2.3.4:1234/2345"
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            &dummy_cryptde as &dyn CryptDE,
                            "masq://eth-mainnet:Si06R3ulkOjJOLw1r2R9GOsY87yuinHU_IHK2FJyGnk@2.3.4.5:3456/4567"
                        ))
                        .unwrap()
                    ],
                    DEFAULT_RATE_PACK
                )
            })
        );
    }

    #[test]
    fn make_neighborhood_config_standard_missing_ip() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "standard")
                    .param(
                        "--neighbors",
                        "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345,masq://eth-mainnet:VGVk@2.3.4.5:3456/4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration()),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode standard without --ip specified"
            ))
        )
    }

    #[test]
    fn make_neighborhood_config_originate_only_doesnt_need_ip() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "originate-only")
                    .param(
                        "--neighbors",
                        "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345,masq://eth-mainnet:VGVk@2.3.4.5:3456/4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration()),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Ok(NeighborhoodConfig {
                mode: NeighborhoodMode::OriginateOnly(
                    vec![
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345"
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:VGVk@2.3.4.5:3456/4567"
                        ))
                        .unwrap()
                    ],
                    DEFAULT_RATE_PACK
                )
            })
        );
    }

    #[test]
    fn make_neighborhood_config_originate_only_does_need_at_least_one_neighbor() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "originate-only")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration().check_password_result(Ok(false))),
            &mut BootstrapperConfig::new(),
        );

        assert_eq! (result, Err(ConfiguratorError::required("neighborhood-mode", "Node cannot run as --neighborhood-mode originate-only without --neighbors specified")))
    }

    #[test]
    fn make_neighborhood_config_consume_only_doesnt_need_ip() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "consume-only")
                    .param(
                        "--neighbors",
                        "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345,masq://eth-mainnet:VGVk@2.3.4.5:3456/4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration()),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Ok(NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![
                    NodeDescriptor::try_from((
                        main_cryptde(),
                        "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345"
                    ))
                    .unwrap(),
                    NodeDescriptor::try_from((
                        main_cryptde(),
                        "masq://eth-mainnet:VGVk@2.3.4.5:3456/4567"
                    ))
                    .unwrap()
                ],)
            })
        );
    }

    #[test]
    fn make_neighborhood_config_consume_only_rejects_dns_servers_and_needs_at_least_one_neighbor() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "consume-only")
                    .param("--dns-servers", "1.1.1.1")
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration()),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode consume-only without --neighbors specified"
            )
            .another_required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode consume-only if --dns-servers is specified"
            ))
        )
    }

    #[test]
    fn make_neighborhood_config_zero_hop_doesnt_need_ip_or_neighbors() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration().check_password_result(Ok(false))),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Ok(NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop
            })
        );
    }

    #[test]
    fn make_neighborhood_config_zero_hop_cant_tolerate_ip() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .param("--ip", "1.2.3.4")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration().check_password_result(Ok(false))),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode zero-hop if --ip is specified"
            ))
        )
    }

    #[test]
    fn make_neighborhood_config_zero_hop_cant_tolerate_neighbors() {
        running_test();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--neighborhood-mode", "zero-hop")
                    .param(
                        "--neighbors",
                        "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345,masq://eth-mainnet:VGVk@2.3.4.5:3456/4567",
                    )
                    .param("--fake-public-key", "booga")
                    .into(),
            ))],
        )
        .unwrap();

        let result = standard::make_neighborhood_config(
            &multi_config,
            Some(&mut make_default_persistent_configuration()),
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighborhood-mode",
                "Node cannot run as --neighborhood-mode zero-hop if --neighbors is specified"
            ))
        )
    }

    #[test]
    fn get_past_neighbors_handles_good_password_but_no_past_neighbors() {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut persistent_config =
            make_default_persistent_configuration().past_neighbors_result(Ok(None));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());

        let result = standard::get_past_neighbors(
            &multi_config,
            &mut persistent_config,
            &mut unprivileged_config,
        )
        .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn get_past_neighbors_handles_unavailable_password() {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut persistent_config =
            make_default_persistent_configuration().check_password_result(Ok(true));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());

        let result = standard::get_past_neighbors(
            &multi_config,
            &mut persistent_config,
            &mut unprivileged_config,
        )
        .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn get_past_neighbors_handles_non_password_error() {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(false))
            .past_neighbors_result(Err(PersistentConfigError::NotPresent));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());

        let result = standard::get_past_neighbors(
            &multi_config,
            &mut persistent_config,
            &mut unprivileged_config,
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::new(vec![ParamError::new(
                "[past neighbors]",
                "NotPresent"
            )]))
        );
    }

    #[test]
    fn convert_ci_configs_handles_leftover_whitespaces_between_descriptors_and_commas() {
        let multi_config = make_simplified_multi_config([
            "program",
            "--chain",
            "eth-ropsten",
            "--fake-public-key",
            "ABCDE",
            "--neighbors",
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@1.2.3.4:5555, masq://eth-ropsten:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542 , masq://eth-ropsten:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504",
        ]);
        let public_key = PublicKey::new(b"ABCDE");
        let cryptde = CryptDENull::from(&public_key, Chain::EthRopsten);
        let cryptde_traitified = &cryptde as &dyn CryptDE;

        let result = standard::convert_ci_configs(&multi_config);

        assert_eq!(result, Ok(Some(
            vec![
                NodeDescriptor::try_from((cryptde_traitified, "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@1.2.3.4:5555")).unwrap(),
                NodeDescriptor::try_from((cryptde_traitified, "masq://eth-ropsten:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542")).unwrap(),
                NodeDescriptor::try_from((cryptde_traitified, "masq://eth-ropsten:A6PGHT3rRjaeFpD_rFi3qGEXAVPq7bJDfEUZpZaIyq8@14.10.50.6:10504")).unwrap()])
            )
        )
    }

    #[test]
    fn convert_ci_configs_does_not_like_neighbors_with_bad_syntax() {
        running_test();
        let multi_config = make_simplified_multi_config(["program", "--neighbors", "ooga,booga"]);

        let result = standard::convert_ci_configs(&multi_config).err();

        assert_eq!(
            result,
            Some(ConfiguratorError::new(vec![
                ParamError::new(
                    "neighbors",
                    "Prefix or more missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'ooga'"
                ),
                ParamError::new(
                    "neighbors",
                    "Prefix or more missing. Should be 'masq://<chain identifier>:<public key>@<node address>', not 'booga'"
                ),
            ]))
        );
    }

    #[test]
    fn convert_ci_configs_complains_about_descriptor_without_node_address_when_mainnet_required() {
        let descriptor = format!(
            "masq://{}:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@:",
            DEFAULT_CHAIN.rec().literal_identifier
        );
        let multi_config = make_simplified_multi_config(["program", "--neighbors", &descriptor]);

        let result = standard::convert_ci_configs(&multi_config);

        assert_eq!(result,Err(ConfiguratorError::new(vec![ParamError::new("neighbors", &format!("Neighbors supplied without ip addresses and ports are not valid: '{}<N/A>:<N/A>",&descriptor[..descriptor.len()-1]))])));
    }

    #[test]
    fn convert_ci_configs_complains_about_descriptor_without_node_address_when_test_chain_required()
    {
        let multi_config = make_simplified_multi_config([
            "program",
            "--chain",
            "eth-ropsten",
            "--neighbors",
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@:",
        ]);

        let result = standard::convert_ci_configs(&multi_config);

        assert_eq!(result,Err(ConfiguratorError::new(vec![ParamError::new("neighbors", "Neighbors supplied without ip addresses and ports are not valid: 'masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@<N/A>:<N/A>")])))
    }

    #[test]
    fn server_initializer_collected_params_can_read_parameters_from_config_file() {
        running_test();
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
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
            &["", "--data-directory", home_dir.to_str().unwrap()].array_of_borrows_to_vec(),
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
            "node_configurator",
            "can_read_wallet_parameters_from_config_file",
        );
        let mut persistent_config = PersistentConfigurationReal::new(Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir.clone(), TEST_DEFAULT_CHAIN, true)
                .unwrap(),
        )));
        let consuming_private_key =
            "89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF89ABCDEF";
        let config_file_path = home_dir.join("config.toml");
        {
            let mut config_file = File::create(&config_file_path).unwrap();
            short_writeln!(
                config_file,
                "consuming-private-key = \"{}\"",
                consuming_private_key
            );
        }
        let args = ArgsBuilder::new()
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--ip", "1.2.3.4");
        let mut bootstrapper_config = BootstrapperConfig::new();
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![
                Box::new(CommandLineVcl::new(args.into())),
                Box::new(ConfigFileVcl::new(&config_file_path, false).unwrap()),
            ],
        )
        .unwrap();

        standard::privileged_parse_args(
            &DirsWrapperReal {},
            &multi_config,
            &mut bootstrapper_config,
        )
        .unwrap();
        standard::unprivileged_parse_args(
            &multi_config,
            &mut bootstrapper_config,
            Some(&mut persistent_config),
        )
        .unwrap();
        let consuming_private_key_bytes: Vec<u8> = consuming_private_key.from_hex().unwrap();
        let consuming_keypair =
            Bip32ECKeyPair::from_raw_secret(consuming_private_key_bytes.as_ref()).unwrap();
        assert_eq!(
            bootstrapper_config.consuming_wallet,
            Some(Wallet::from(consuming_keypair)),
        );

        let public_key = PublicKey::new(&[1, 2, 3]);
        let payer = bootstrapper_config
            .consuming_wallet
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
            "node_configurator",
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
            .param("--real-user", "999:999:/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();

        standard::privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

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
                mode: NeighborhoodMode::ZeroHop // not populated on the privileged side
            }
        );
        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url_opt,
            Some("http://127.0.0.1:8545".to_string()),
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
    fn unprivileged_parse_args_creates_configurations() {
        running_test();
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator",
            "unprivileged_parse_args_creates_configurations",
        );
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir.clone(), TEST_DEFAULT_CHAIN, true)
                .unwrap(),
        ));
        let consuming_private_key_text =
            "ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01ABCDEF01";
        let consuming_private_key = PlainData::from_str(consuming_private_key_text).unwrap();
        let mut persistent_config = PersistentConfigurationReal::new(config_dao);
        let password = "secret-db-password";
        let args = ArgsBuilder::new()
            .param("--config-file", "specified_config.toml")
            .param("--dns-servers", "12.34.56.78,23.45.67.89")
            .param(
                "--neighbors",
                "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345,masq://eth-mainnet:VGVk@2.3.4.5:3456/4567",
            )
            .param("--ip", "34.56.78.90")
            .param("--clandestine-port", "1234")
            .param("--ui-port", "5335")
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--blockchain-service-url", "http://127.0.0.1:8545")
            .param("--log-level", "trace")
            .param("--fake-public-key", "AQIDBA")
            .param("--db-password", password)
            .param(
                "--earning-wallet",
                "0x0123456789012345678901234567890123456789",
            )
            .param("--consuming-private-key", consuming_private_key_text)
            .param("--real-user", "999:999:/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();

        standard::unprivileged_parse_args(&multi_config, &mut config, Some(&mut persistent_config))
            .unwrap();

        assert_eq!(
            value_m!(multi_config, "config-file", PathBuf),
            Some(PathBuf::from("specified_config.toml")),
        );
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap()
        );
        assert_eq!(Some(1234u16), config.clandestine_port_opt);
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0x0123456789012345678901234567890123456789").unwrap()
        );
        assert_eq!(
            config.consuming_wallet,
            Some(Wallet::from(
                Bip32ECKeyPair::from_raw_secret(consuming_private_key.as_slice()).unwrap()
            )),
        );
        assert_eq!(
            config.neighborhood_config,
            NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::from_str("34.56.78.90").unwrap(), &[]),
                    vec![
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:QmlsbA@1.2.3.4:1234/2345"
                        ))
                        .unwrap(),
                        NodeDescriptor::try_from((
                            main_cryptde(),
                            "masq://eth-mainnet:VGVk@2.3.4.5:3456/4567"
                        ))
                        .unwrap(),
                    ],
                    DEFAULT_RATE_PACK.clone()
                )
            }
        );
    }

    #[test]
    fn unprivileged_parse_args_creates_configuration_with_defaults() {
        running_test();
        let args = ArgsBuilder::new().param("--ip", "1.2.3.4");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            Some(&mut make_default_persistent_configuration().check_password_result(Ok(false))),
        )
        .unwrap();

        assert_eq!(
            Some(PathBuf::from("config.toml")),
            value_m!(multi_config, "config-file", PathBuf)
        );
        assert_eq!(None, config.clandestine_port_opt);
        assert!(config
            .neighborhood_config
            .mode
            .neighbor_configs()
            .is_empty());
        assert_eq!(
            config
                .neighborhood_config
                .mode
                .node_addr_opt()
                .unwrap()
                .ip_addr(),
            IpAddr::from_str("1.2.3.4").unwrap(),
        );
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone(),);
        assert_eq!(config.consuming_wallet, None,);
    }

    #[test]
    fn unprivileged_parse_args_with_neighbor_in_database_but_not_command_line() {
        running_test();
        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--fake-public-key", "BORSCHT")
            .param("--db-password", "password");
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_configuration = make_persistent_config(
            None,
            Some("password"),
            None,
            None,
            None,
            Some("masq://eth-ropsten:AQIDBA@1.2.3.4:1234,masq://eth-ropsten:AgMEBQ@2.3.4.5:2345"),
        )
        .past_neighbors_params(&past_neighbors_params_arc);

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            Some(&mut persistent_configuration),
        )
        .unwrap();

        assert_eq!(
            config.neighborhood_config.mode.neighbor_configs(),
            &[
                NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-ropsten:AQIDBA@1.2.3.4:1234"
                ))
                .unwrap(),
                NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-ropsten:AgMEBQ@2.3.4.5:2345"
                ))
                .unwrap(),
            ]
        );
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(past_neighbors_params[0], "password".to_string());
    }

    #[test]
    fn privileged_parse_args_creates_configuration_with_defaults() {
        running_test();
        let args = ArgsBuilder::new().param("--ip", "1.2.3.4");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();

        standard::privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

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
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();

        standard::privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

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

    fn make_persistent_config(
        mnemonic_seed_prefix_opt: Option<&str>,
        db_password_opt: Option<&str>,
        consuming_wallet_derivation_path_opt: Option<&str>,
        earning_wallet_address_opt: Option<&str>,
        gas_price_opt: Option<&str>,
        past_neighbors_opt: Option<&str>,
    ) -> PersistentConfigurationMock {
        let (mnemonic_seed_result, mnemonic_seed_exists_result) =
            match (mnemonic_seed_prefix_opt, db_password_opt) {
                (None, None) => (Ok(None), Ok(false)),
                (None, Some(_)) => (Ok(None), Ok(false)),
                (Some(mnemonic_seed_prefix), _) => {
                    (Ok(Some(make_mnemonic_seed(mnemonic_seed_prefix))), Ok(true))
                }
            };
        let consuming_wallet_derivation_path_opt =
            consuming_wallet_derivation_path_opt.map(|x| x.to_string());
        let earning_wallet_from_address_opt = match earning_wallet_address_opt {
            None => None,
            Some(address) => Some(Wallet::from_str(address).unwrap()),
        };
        let gas_price = gas_price_opt
            .unwrap_or(DEFAULT_GAS_PRICE)
            .parse::<u64>()
            .unwrap();
        let past_neighbors_result = match (past_neighbors_opt, db_password_opt) {
            (Some(past_neighbors), Some(_)) => Ok(Some(
                past_neighbors
                    .split(",")
                    .map(|s| NodeDescriptor::try_from((main_cryptde(), s)).unwrap())
                    .collect::<Vec<NodeDescriptor>>(),
            )),
            _ => Ok(None),
        };
        PersistentConfigurationMock::new()
            .mnemonic_seed_result(mnemonic_seed_result)
            .mnemonic_seed_exists_result(mnemonic_seed_exists_result)
            .consuming_wallet_derivation_path_result(Ok(consuming_wallet_derivation_path_opt))
            .earning_wallet_from_address_result(Ok(earning_wallet_from_address_opt))
            .gas_price_result(Ok(gas_price))
            .past_neighbors_result(past_neighbors_result)
    }

    fn make_mnemonic_seed(prefix: &str) -> PlainData {
        let mut bytes: Vec<u8> = vec![];
        while bytes.len() < 64 {
            bytes.extend(prefix.as_bytes())
        }
        bytes.truncate(64);
        let result = PlainData::from(bytes);
        result
    }

    #[test]
    fn get_wallets_with_brand_new_database_establishes_default_earning_wallet_without_requiring_password(
    ) {
        running_test();
        let args = ["program"];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(None, None, None, None, None, None);
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(config.consuming_wallet, None);
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone());
    }

    #[test]
    fn get_wallets_handles_failure_of_mnemonic_seed_exists() {
        let args = ["program"];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_from_address_result(Ok(None))
            .mnemonic_seed_exists_result(Err(PersistentConfigError::NotPresent));

        let result = standard::get_wallets(
            &multi_config,
            &mut persistent_config,
            &mut BootstrapperConfig::new(),
        );

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("seed"))
        );
    }

    #[test]
    fn get_wallets_handles_failure_of_consuming_wallet_derivation_path() {
        let args = ["program"];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_from_address_result(Ok(None))
            .mnemonic_seed_exists_result(Ok(true))
            .consuming_wallet_derivation_path_result(Err(PersistentConfigError::NotPresent));
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());

        let result = standard::get_wallets(&multi_config, &mut persistent_config, &mut config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("consuming-private-key"))
        );
    }

    #[test]
    fn earning_wallet_address_different_from_database() {
        running_test();
        let args = [
            "program",
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
        ];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(
            None,
            None,
            None,
            Some("0x9876543210987654321098765432109876543210"),
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        let result =
            standard::get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq! (result, Some (ConfiguratorError::new (vec![
            ParamError::new ("earning-wallet", "Cannot change to an address (0x0123456789012345678901234567890123456789) different from that previously set (0x9876543210987654321098765432109876543210)")
        ])));
    }

    #[test]
    fn earning_wallet_address_matches_database() {
        running_test();
        let args = [
            "program",
            "--earning-wallet",
            "0xb00fa567890123456789012345678901234B00FA",
        ];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(
            None,
            None,
            None,
            Some("0xB00FA567890123456789012345678901234b00fa"),
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(
            config.earning_wallet,
            Wallet::new("0xb00fa567890123456789012345678901234b00fa")
        );
    }

    #[test]
    fn consuming_wallet_private_key_plus_mnemonic_seed() {
        running_test();
        let consuming_private_key_hex =
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD";
        let args = [
            "program",
            "--db-password",
            "password",
            "--consuming-private-key",
            consuming_private_key_hex,
        ];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        let result =
            standard::get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq! (result, Some (ConfiguratorError::new (vec![
            ParamError::new ("consuming-private-key", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information")
        ])));
    }

    #[test]
    fn earning_wallet_address_plus_mnemonic_seed() {
        running_test();
        let args = [
            "program",
            "--db-password",
            "password",
            "--earning-wallet",
            "0xcafedeadbeefbabefacecafedeadbeefbabeface",
        ];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        let result =
            standard::get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq! (result, Some (ConfiguratorError::new (vec![
            ParamError::new ("earning-wallet", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information")
        ])));
    }

    #[test]
    fn consuming_wallet_derivation_path_plus_earning_wallet_address_plus_mnemonic_seed() {
        running_test();
        let args = ["program", "--db-password", "password"];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
        )
        .check_password_result(Ok(false));
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
        let expected_consuming_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(mnemonic_seed.as_ref(), "m/44'/60'/1'/2/3").unwrap(),
        );
        assert_eq!(config.consuming_wallet, Some(expected_consuming_wallet));
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap()
        );
    }

    #[test]
    fn consuming_wallet_derivation_path_plus_mnemonic_seed_with_no_db_password_parameter() {
        running_test();
        let args = ["program"];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
        )
        .check_password_result(Ok(false));
        let mut config = BootstrapperConfig::new();

        standard::get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(config.consuming_wallet, None);
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap()
        );
    }

    #[test]
    fn unprivileged_parse_args_with_invalid_consuming_wallet_private_key_reacts_correctly() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_with_invalid_consuming_wallet_private_key_panics_correctly",
        );

        let args = ArgsBuilder::new().param("--data-directory", home_directory.to_str().unwrap());
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key",
            &"not valid hex",
        ))];

        let faux_environment = CommandLineVcl::from(vcl_args);

        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVcl::new(args.into())),
        ];

        let result = make_new_test_multi_config(&app_node(), vcls).err().unwrap();

        assert_eq!(
            result,
            ConfiguratorError::required("consuming-private-key", "Invalid value: not valid hex")
        )
    }

    #[test]
    fn unprivileged_parse_args_consuming_private_key_happy_path() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "parse_args_consuming_private_key_happy_path",
        );

        let args = ArgsBuilder::new()
            .param("--ip", "1.2.3.4")
            .param("--data-directory", home_directory.to_str().unwrap())
            .opt("--db-password");
        let vcl_args: Vec<Box<dyn VclArg>> = vec![Box::new(NameValueVclArg::new(
            &"--consuming-private-key",
            &"cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ))];

        let faux_environment = CommandLineVcl::from(vcl_args);

        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(faux_environment),
            Box::new(CommandLineVcl::new(args.into())),
        ];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
        let stdout_writer = &mut ByteArrayWriter::new();

        standard::unprivileged_parse_args(
            &multi_config,
            &mut config,
            Some(&mut make_default_persistent_configuration()),
        )
        .unwrap();

        let captured_output = stdout_writer.get_string();
        let expected_output = "";
        assert!(config.consuming_wallet.is_some());
        assert_eq!(
            format!("{}", config.consuming_wallet.unwrap()),
            "0x8e4d2317e56c8fd1fc9f13ba2aa62df1c5a542a7".to_string()
        );
        assert_eq!(captured_output, expected_output);
    }

    #[test]
    fn get_db_password_shortcuts_if_its_already_gotten() {
        running_test();
        let args = ["program"];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mut config = BootstrapperConfig::new();
        let mut persistent_config =
            make_default_persistent_configuration().check_password_result(Ok(false));
        config.db_password_opt = Some("password".to_string());

        let result = standard::get_db_password(&multi_config, &mut config, &mut persistent_config);

        assert_eq!(result, Ok(Some("password".to_string())));
    }

    #[test]
    fn get_db_password_doesnt_bother_if_database_has_no_password_yet() {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut config = BootstrapperConfig::new();
        let mut persistent_config =
            make_default_persistent_configuration().check_password_result(Ok(true));

        let result = standard::get_db_password(&multi_config, &mut config, &mut persistent_config);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn get_db_password_handles_database_write_error() {
        running_test();
        let args = ["command", "--db-password", "password"];
        let multi_config = pure_test_utils::make_simplified_multi_config(args);
        let mut config = BootstrapperConfig::new();
        let mut persistent_config = make_default_persistent_configuration()
            .check_password_result(Ok(true))
            .check_password_result(Ok(true))
            .check_password_result(Ok(true))
            .change_password_result(Err(NotPresent));

        let result = standard::get_db_password(&multi_config, &mut config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("db-password"))
        );
    }

    #[test]
    fn no_parameters_produces_configuration_for_crash_point() {
        running_test();
        let args = make_default_cli_params();
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_test_multi_config(&app_node(), vec![vcl]).unwrap();

        standard::privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        assert_eq!(config.crash_point, CrashPoint::None);
    }

    #[test]
    fn with_parameters_produces_configuration_for_crash_point() {
        running_test();
        let args = make_default_cli_params().param("--crash-point", "panic");
        let mut config = BootstrapperConfig::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_test_multi_config(&app_node(), vec![vcl]).unwrap();

        standard::privileged_parse_args(&DirsWrapperReal {}, &multi_config, &mut config).unwrap();

        assert_eq!(config.crash_point, CrashPoint::Panic);
    }

    #[test]
    fn server_initializer_collected_params_senses_when_user_specifies_config_file() {
        running_test();
        let data_dir = ensure_node_home_directory_exists(
            "node_configurator_standard",
            "server_initializer_collected_params_senses_when_user_specifies_config_file",
        );
        let args = ArgsBuilder::new().param("--config-file", "booga.toml"); // nonexistent config file: should stimulate panic because user-specified
        let args_vec: Vec<String> = args.into();
        let dir_wrapper = DirsWrapperMock::new()
            .home_dir_result(Some(PathBuf::from("/unexisting_home/unexisting_alice")))
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
        let args = ["program", "--ip", "1.2.3.4", "--chain", "dev"];

        let config = subject
            .configure(&make_simplified_multi_config(args))
            .unwrap();

        assert_eq!(config.blockchain_bridge_config.chain, Chain::from("dev"));
    }

    #[test]
    fn privileged_configuration_accepts_network_chain_selection_for_ropsten() {
        running_test();
        let subject = NodeConfiguratorStandardPrivileged::new();
        let args = [
            "program",
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
        let args = ["program", "--ip", "1.2.3.4"];

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
            "program",
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
        let args = ["program", "--ip", "1.2.3.4", "--gas-price", "57"];

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
        let args = ["program", "--ip", "1.2.3.4"];

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
    fn configure_database_with_data_specified_on_command_line_but_not_in_database_without_seed() {
        running_test();
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        let earning_address = "0x0123456789012345678901234567890123456789";
        let consuming_private_key_text =
            "ABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EF";
        let consuming_private_key = PlainData::from_str(consuming_private_key_text).unwrap();
        let gas_price = 4u64;
        let keypair = Bip32ECKeyPair::from_raw_secret(consuming_private_key.as_slice()).unwrap();
        config.earning_wallet = Wallet::new(earning_address);
        config.consuming_wallet = Some(Wallet::from(keypair));
        config.blockchain_bridge_config.gas_price = gas_price;
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let set_gas_price_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(Ok(None))
            .consuming_wallet_derivation_path_result(Ok(None))
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_clandestine_port_result(Ok(()))
            .set_gas_price_params(&set_gas_price_params_arc)
            .set_gas_price_result(Ok(()));

        let result = standard::configure_database(&config, &mut persistent_config);

        assert_eq!(result, Ok(()));
        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        assert_eq!(*set_clandestine_port_params, vec![1234]);
        let set_gas_price_params = set_gas_price_params_arc.lock().unwrap();
        assert_eq!(*set_gas_price_params, vec![gas_price]);
    }

    #[test]
    fn configure_database_with_data_specified_on_command_line_and_in_database_without_seed() {
        running_test();
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        let earning_address = "0x0123456789012345678901234567890123456789";
        let consuming_private_key_text =
            "ABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EFABCD00EF";
        let consuming_private_key = PlainData::from_str(consuming_private_key_text).unwrap();
        let keypair = Bip32ECKeyPair::from_raw_secret(consuming_private_key.as_slice()).unwrap();
        config.consuming_wallet = Some(Wallet::from(keypair));
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(Ok(Some(earning_address.to_string())))
            .consuming_wallet_derivation_path_result(Ok(None))
            .set_gas_price_result(Ok(()))
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_clandestine_port_result(Ok(()));

        let result = standard::configure_database(&config, &mut persistent_config);

        assert_eq!(result, Ok(()));
        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        assert_eq!(*set_clandestine_port_params, vec![1234]);
    }

    #[test]
    fn configure_database_with_no_data_specified() {
        running_test();
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = None;
        config.consuming_wallet = None;
        config.earning_wallet = DEFAULT_EARNING_WALLET.clone();
        let set_clandestine_port_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(Ok(None))
            .consuming_wallet_derivation_path_result(Ok(None))
            .set_gas_price_result(Ok(()))
            .set_clandestine_port_params(&set_clandestine_port_params_arc)
            .set_clandestine_port_result(Ok(()));

        let result = standard::configure_database(&config, &mut persistent_config);

        assert_eq!(result, Ok(()));
        let set_clandestine_port_params = set_clandestine_port_params_arc.lock().unwrap();
        let no_ports: Vec<u16> = vec![];
        assert_eq!(*set_clandestine_port_params, no_ports);
    }
}
