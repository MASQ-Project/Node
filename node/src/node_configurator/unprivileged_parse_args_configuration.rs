// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::bip32::Bip32ECKeyProvider;
use crate::bootstrapper::BootstrapperConfig;
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::accountant::{AccountantConfig, DEFAULT_EARNING_WALLET};
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::neighborhood::{NeighborhoodConfig, NeighborhoodMode, NodeDescriptor};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use clap::value_t;
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::{DEFAULT_CHAIN, DEFAULT_RATE_PACK, MASQ_URL_PREFIX};
use masq_lib::logger::Logger;
use masq_lib::multi_config::make_arg_matches_accesible;
use masq_lib::multi_config::MultiConfig;
use masq_lib::payment_curves_and_rate_pack::{PaymentCurves, RatePack};
use masq_lib::shared_schema::{ConfiguratorError, ParamError};
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use masq_lib::utils::{AutomapProtocol, ExpectValue, WrapResult};
use rustc_hex::FromHex;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

pub trait ParseArgsConfiguration {
    // Only initialization that cannot be done with privilege should happen here.
    fn unprivileged_parse_args(
        &self,
        multi_config: &MultiConfig,
        unprivileged_config: &mut BootstrapperConfig,
        persistent_config: &mut dyn PersistentConfiguration,
        logger: &Logger,
    ) -> Result<(), ConfiguratorError> {
        unprivileged_config
            .blockchain_bridge_config
            .blockchain_service_url_opt =
            if is_user_specified(multi_config, "blockchain-service-url") {
                value_m!(multi_config, "blockchain-service-url", String)
            } else {
                match persistent_config.blockchain_service_url() {
                    Ok(Some(price)) => Some(price),
                    Ok(None) => None,
                    Err(pce) => return Err(pce.into_configurator_error("gas-price")),
                }
            };
        unprivileged_config.clandestine_port_opt = value_m!(multi_config, "clandestine-port", u16);
        unprivileged_config.blockchain_bridge_config.gas_price =
            if is_user_specified(multi_config, "gas-price") {
                value_m!(multi_config, "gas-price", u64).expectv("gas price")
            } else {
                match persistent_config.gas_price() {
                    Ok(price) => price,
                    Err(pce) => return Err(pce.into_configurator_error("gas-price")),
                }
            };
        configure_accountant_config(multi_config, unprivileged_config, persistent_config)?;
        configure_rate_pack(multi_config, unprivileged_config, persistent_config)?;
        unprivileged_config.mapping_protocol_opt =
            compute_mapping_protocol_opt(multi_config, persistent_config, logger);
        let mnc_result = {
            get_wallets(multi_config, persistent_config, unprivileged_config)?;
            make_neighborhood_config(self, multi_config, persistent_config, unprivileged_config)
        };

        mnc_result.map(|config| unprivileged_config.neighborhood_config = config)
    }

    fn get_past_neighbors(
        &self,
        multi_config: &MultiConfig,
        persistent_config: &mut dyn PersistentConfiguration,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<Vec<NodeDescriptor>, ConfiguratorError>;
}

pub struct ParseArgsConfigurationDaoReal {}

impl ParseArgsConfiguration for ParseArgsConfigurationDaoReal {
    fn get_past_neighbors(
        &self,
        multi_config: &MultiConfig,
        persistent_config: &mut dyn PersistentConfiguration,
        unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<Vec<NodeDescriptor>, ConfiguratorError> {
        Ok(
            match &get_db_password(multi_config, unprivileged_config, persistent_config)? {
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
}

pub struct ParseArgsConfigurationDaoNull {}

impl ParseArgsConfiguration for ParseArgsConfigurationDaoNull {
    fn get_past_neighbors(
        &self,
        _multi_config: &MultiConfig,
        _persistent_config: &mut dyn PersistentConfiguration,
        _unprivileged_config: &mut BootstrapperConfig,
    ) -> Result<Vec<NodeDescriptor>, ConfiguratorError> {
        Ok(vec![])
    }
}

fn get_wallets(
    multi_config: &MultiConfig,
    persistent_config: &mut dyn PersistentConfiguration,
    config: &mut BootstrapperConfig,
) -> Result<(), ConfiguratorError> {
    let mnemonic_seed_exists = match persistent_config.mnemonic_seed_exists() {
        Ok(flag) => flag,
        Err(pce) => return Err(pce.into_configurator_error("seed")),
    };
    validate_testing_parameters(mnemonic_seed_exists, multi_config)?;
    let earning_wallet_opt = get_earning_wallet_from_address(multi_config, persistent_config)?;
    let mut consuming_wallet_opt = get_consuming_wallet_from_private_key(multi_config)?;

    if (earning_wallet_opt.is_none() || consuming_wallet_opt.is_none()) && mnemonic_seed_exists {
        if let Some(db_password) = get_db_password(multi_config, config, persistent_config)? {
            if consuming_wallet_opt.is_none() {
                consuming_wallet_opt =
                    get_consuming_wallet_opt_from_derivation_path(persistent_config, &db_password)?;
            } else {
                match persistent_config.consuming_wallet_derivation_path() {
                    Ok(Some(_)) => return Err(ConfiguratorError::required("consuming-private-key", "Cannot use when database contains mnemonic seed and consuming wallet derivation path")),
                    Ok(None) => (),
                    Err(pce) => return Err(pce.into_configurator_error("consuming-wallet")),
                }
            }
        }
    }
    config.consuming_wallet_opt = consuming_wallet_opt;
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

fn get_earning_wallet_from_address(
    multi_config: &MultiConfig,
    persistent_config: &dyn PersistentConfiguration,
) -> Result<Option<Wallet>, ConfiguratorError> {
    let earning_wallet_from_command_line_opt = value_m!(multi_config, "earning-wallet", String);
    let earning_wallet_from_database_opt = match persistent_config.earning_wallet_from_address() {
        Ok(ewfdo) => ewfdo,
        Err(e) => return Err(e.into_configurator_error("earning-wallet")),
    };
    match (
        earning_wallet_from_command_line_opt,
        earning_wallet_from_database_opt,
    ) {
        (None, None) => Ok(None),
        (Some(address), None) => Ok(Some(
            Wallet::from_str(&address).expect("--earning-wallet not properly constrained by clap"),
        )),
        (None, Some(wallet)) => Ok(Some(wallet)),
        (Some(address), Some(wallet)) => {
            if wallet.to_string().to_lowercase() == address.to_lowercase() {
                Ok(Some(wallet))
            } else {
                Err(ConfiguratorError::required(
                    "earning-wallet",
                    &format!(
                        "Cannot change to an address ({}) different from that previously set ({})",
                        address.to_lowercase(),
                        wallet.to_string().to_lowercase()
                    ),
                ))
            }
        }
    }
}

fn get_consuming_wallet_from_private_key(
    multi_config: &MultiConfig,
) -> Result<Option<Wallet>, ConfiguratorError> {
    match value_m!(multi_config, "consuming-private-key", String) {
        Some(consuming_private_key_string) => {
            match consuming_private_key_string.from_hex::<Vec<u8>>() {
                Ok(raw_secret) => match Bip32ECKeyProvider::from_raw_secret(&raw_secret[..]) {
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

fn get_consuming_wallet_opt_from_derivation_path(
    persistent_config: &dyn PersistentConfiguration,
    db_password: &str,
) -> Result<Option<Wallet>, ConfiguratorError> {
    match persistent_config.consuming_wallet_derivation_path() {
        Ok(None) => Ok(None),
        Ok(Some(derivation_path)) => match persistent_config.mnemonic_seed(db_password) {
            Ok(None) => Ok(None),
            Ok(Some(mnemonic_seed)) => {
                let keypair = Bip32ECKeyProvider::try_from((
                    mnemonic_seed.as_ref(),
                    derivation_path.as_str(),
                ))
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

pub fn make_neighborhood_config<T: ParseArgsConfiguration + ?Sized>(
    pars_args_configurator: &T,
    multi_config: &MultiConfig,
    persistent_config: &mut dyn PersistentConfiguration,
    unprivileged_config: &mut BootstrapperConfig,
) -> Result<NeighborhoodConfig, ConfiguratorError> {
    let neighbor_configs: Vec<NodeDescriptor> = {
        match convert_ci_configs(multi_config)? {
            Some(configs) => configs,
            None => pars_args_configurator.get_past_neighbors(
                multi_config,
                persistent_config,
                unprivileged_config,
            )?,
        }
    };
    match make_neighborhood_mode(multi_config, neighbor_configs, persistent_config) {
        Ok(mode) => Ok(NeighborhoodConfig { mode }),
        Err(e) => Err(e),
    }
}

fn make_neighborhood_mode(
    multi_config: &MultiConfig,
    neighbor_configs: Vec<NodeDescriptor>,
    persistent_config: &mut dyn PersistentConfiguration,
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
            if value_m!(multi_config, "ip", IpAddr).is_some() {
                Err(ConfiguratorError::required(
                    "neighborhood-mode",
                    "Node cannot run as --neighborhood-mode zero-hop if --ip is specified",
                ))
            } else {
                if !neighbor_configs.is_empty() {
                    let password_opt = value_m!(multi_config, "db-password", String);
                    zero_hop_neighbors_configuration(
                        password_opt,
                        neighbor_configs,
                        persistent_config,
                    )?
                }
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

fn zero_hop_neighbors_configuration(
    password_opt: Option<String>,
    descriptors: Vec<NodeDescriptor>,
    persistent_config: &mut dyn PersistentConfiguration,
) -> Result<(), ConfiguratorError> {
    match password_opt {
        Some(password) => {
            if let Err(e) = persistent_config.set_past_neighbors(Some(descriptors), &password) {
                return Err(e.into_configurator_error("neighbors"));
            }
        }
        None => {
            return Err(ConfiguratorError::required(
                "neighbors",
                "Cannot proceed without a password",
            ));
        }
    }
    Ok(())
}

fn neighborhood_mode_standard(
    multi_config: &MultiConfig,
    neighbor_configs: Vec<NodeDescriptor>,
) -> Result<NeighborhoodMode, ConfiguratorError> {
    let ip = get_public_ip(multi_config)?;
    Ok(NeighborhoodMode::Standard(
        NodeAddr::new(&ip, &[]),
        neighbor_configs,
        DEFAULT_RATE_PACK,
    ))
}

fn get_public_ip(multi_config: &MultiConfig) -> Result<IpAddr, ConfiguratorError> {
    match value_m!(multi_config, "ip", String) {
        Some(ip_str) => match IpAddr::from_str(&ip_str) {
            Ok(ip_addr) => Ok(ip_addr),
            Err(_) => todo!("Drive in a better error message"), //Err(ConfiguratorError::required("ip", &format! ("blockety blip: '{}'", ip_str),
        },
        None => Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))), // sentinel: means "Try Automap"
    }
}

fn convert_ci_configs(
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
                let results =
                    validate_descriptors_from_user(separate_configs, dummy_cryptde, desired_chain);
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
    desired_native_chain: Chain,
) -> Vec<Result<NodeDescriptor, ParamError>> {
    descriptors.into_iter().map(|node_desc_from_ci| {
        let node_desc_trimmed = node_desc_from_ci.trim();
        match NodeDescriptor::try_from((dummy_cryptde.as_ref(), node_desc_trimmed)) {
            Ok(descriptor) => {
                let competence_from_descriptor = descriptor.blockchain;
                if desired_native_chain == competence_from_descriptor {
                    validate_mandatory_node_addr(node_desc_trimmed, descriptor)
                } else {
                    let desired_chain = desired_native_chain.rec().literal_identifier;
                    Err(ParamError::new(
                        "neighbors", &format!(
                            "Mismatched chains. You are requiring access to '{}' ({}{}:<public key>@<node address>) with descriptor belonging to '{}'",
                            desired_chain, MASQ_URL_PREFIX,
                            desired_chain,
                            competence_from_descriptor.rec().literal_identifier
                        )
                    ))
                }
            }
            Err(e) => ParamError::new("neighbors", &e).wrap_to_err()
        }
    })
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
            "neighbors",
            &format!(
                "Neighbors supplied without ip addresses and ports are not valid: '{}<N/A>:<N/A>",
                if supplied_descriptor.ends_with("@:") {
                    supplied_descriptor.strip_suffix(':').expect("logic failed")
                } else {
                    supplied_descriptor
                }
            ),
        ))
    }
}

fn compute_mapping_protocol_opt(
    multi_config: &MultiConfig,
    persistent_config: &mut dyn PersistentConfiguration,
    logger: &Logger,
) -> Option<AutomapProtocol> {
    let persistent_mapping_protocol_opt = match persistent_config.mapping_protocol() {
        Ok(mp_opt) => mp_opt,
        Err(e) => {
            warning!(
                logger,
                "Could not read mapping protocol from database: {:?}",
                e
            );
            None
        }
    };
    let mapping_protocol_specified = multi_config.occurrences_of("mapping-protocol") > 0;
    let computed_mapping_protocol_opt = match (
        value_m!(multi_config, "mapping-protocol", AutomapProtocol),
        persistent_mapping_protocol_opt,
        mapping_protocol_specified,
    ) {
        (None, Some(persisted_mapping_protocol), false) => Some(persisted_mapping_protocol),
        (None, _, true) => None,
        (cmd_line_mapping_protocol_opt, _, _) => cmd_line_mapping_protocol_opt,
    };
    if computed_mapping_protocol_opt != persistent_mapping_protocol_opt {
        if computed_mapping_protocol_opt.is_none() {
            debug!(logger, "Blanking mapping protocol out of the database")
        }
        match persistent_config.set_mapping_protocol(computed_mapping_protocol_opt) {
            Ok(_) => (),
            Err(e) => {
                warning!(
                    logger,
                    "Could not save mapping protocol to database: {:?}",
                    e
                );
            }
        }
    }
    computed_mapping_protocol_opt
}

fn configure_accountant_config(
    multi_config: &MultiConfig,
    config: &mut BootstrapperConfig,
    persist_config: &mut dyn PersistentConfiguration,
) -> Result<(), ConfiguratorError> {
    let payment_suggested_after_sec = configure_single_parameter_with_checking_overflow(
        multi_config,
        "payment-suggested-after",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| {
            persist_config.payment_suggested_after_sec()
        },
        &mut |interval, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_payment_suggested_after_sec(interval)
        },
    )?;
    let payment_grace_before_ban_sec = configure_single_parameter_with_checking_overflow(
        multi_config,
        "payment-grace-before-ban",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| {
            persist_config.payment_grace_before_ban_sec()
        },
        &mut |interval, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_payment_grace_before_ban_sec(interval)
        },
    )?;
    let permanent_debt_allowed_gwei = configure_single_parameter_with_checking_overflow(
        multi_config,
        "permanent-debt-allowed",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| {
            persist_config.permanent_debt_allowed_gwei()
        },
        &mut |amount, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_permanent_debt_allowed_gwei(amount)
        },
    )?;
    let balance_to_decrease_from_gwei = configure_single_parameter_with_checking_overflow(
        multi_config,
        "balance-to-decrease-from",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| {
            persist_config.balance_to_decrease_from_gwei()
        },
        &mut |amount, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_balance_to_decrease_from_gwei(amount)
        },
    )?;
    let balance_decreases_for_sec = configure_single_parameter_with_checking_overflow(
        multi_config,
        "balance-decreases-for",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| persist_config.balance_decreases_for_sec(),
        &mut |interval, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_balance_decreases_for_sec(interval)
        },
    )?;
    let unban_when_balance_below_gwei = configure_single_parameter_with_checking_overflow(
        multi_config,
        "unban-when-balance-below",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| {
            persist_config.unban_when_balance_below_gwei()
        },
        &mut |amount, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_unban_when_balance_below_gwei(amount)
        },
    )?;
    let payment_curves = PaymentCurves {
        payment_suggested_after_sec,
        payment_grace_before_ban_sec,
        permanent_debt_allowed_gwei,
        balance_to_decrease_from_gwei,
        balance_decreases_for_sec,
        unban_when_balance_below_gwei,
    };
    let pending_payment_interval = Duration::from_secs(configure_single_parameter(
        multi_config,
        "pending-payment-scan-interval",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| {
            persist_config.pending_payment_scan_interval()
        },
        &mut |interval, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_pending_payment_scan_interval(interval)
        },
    )?);
    let payable_interval = Duration::from_secs(configure_single_parameter(
        multi_config,
        "payable-scan-interval",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| persist_config.payable_scan_interval(),
        &mut |interval, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_payable_scan_interval(interval)
        },
    )?);
    let receivable_interval = Duration::from_secs(configure_single_parameter(
        multi_config,
        "receivable-scan-interval",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| persist_config.receivable_scan_interval(),
        &mut |interval, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_receivable_scan_interval(interval)
        },
    )?);
    let accountant_config = AccountantConfig {
        pending_payment_scan_interval_opt: Some(pending_payment_interval),
        payable_scan_interval_opt: Some(payable_interval),
        receivable_scan_interval_opt: Some(receivable_interval),
        payment_curves_opt: Some(payment_curves),
    };
    config.accountant_config = accountant_config;
    Ok(())
}

fn configure_rate_pack(
    multi_config: &MultiConfig,
    config: &mut BootstrapperConfig,
    persist_config: &mut dyn PersistentConfiguration,
) -> Result<(), ConfiguratorError> {
    let routing_byte_rate = configure_single_parameter(
        multi_config,
        "routing-byte-rate",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| persist_config.routing_byte_rate(),
        &mut |rate, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_routing_byte_rate(rate)
        },
    )?;
    let routing_service_rate = configure_single_parameter(
        multi_config,
        "routing-service-rate",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| persist_config.routing_service_rate(),
        &mut |rate, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_routing_service_rate(rate)
        },
    )?;
    let exit_byte_rate = configure_single_parameter(
        multi_config,
        "exit-byte-rate",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| persist_config.exit_byte_rate(),
        &mut |rate, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_exit_byte_rate(rate)
        },
    )?;
    let exit_service_rate = configure_single_parameter(
        multi_config,
        "exit-service-rate",
        persist_config,
        &|persist_config: &dyn PersistentConfiguration| persist_config.exit_service_rate(),
        &mut |rate, persist_config: &mut dyn PersistentConfiguration| {
            persist_config.set_exit_service_rate(rate)
        },
    )?;
    let configured = RatePack {
        routing_byte_rate,
        routing_service_rate,
        exit_byte_rate,
        exit_service_rate,
    };
    config.rate_pack_opt = Some(configured);
    Ok(())
}

fn configure_single_parameter<T, C1, C2>(
    multi_config: &MultiConfig,
    parameter_name: &str,
    persistent_config: &mut dyn PersistentConfiguration,
    persistent_config_getter_method: &C1,
    persistent_config_setter_method: &mut C2,
) -> Result<T, ConfiguratorError>
where
    C1: Fn(&dyn PersistentConfiguration) -> Result<T, PersistentConfigError> + ?Sized,
    C2: FnMut(T, &mut dyn PersistentConfiguration) -> Result<(), PersistentConfigError> + ?Sized,
    T: std::str::FromStr + PartialEq + Copy,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    Ok(
        match (
            value_m!(multi_config, parameter_name, String),
            persistent_config_getter_method(persistent_config),
        ) {
            (Some(rate), pc_result) => {
                let cli_value = rate.parse::<T>().unwrap_or_else(|e|
                    //cannot be tested, behind Clap
                    panic!("Clap let in bad value '{}' for {} due to {}",
                    rate, parameter_name, e));
                let pc_value: T = pc_result.unwrap_or_else(|e| {
                    panic!("{}: database query failed due to {:?}", parameter_name, e)
                });
                if cli_value == pc_value {
                    unimplemented!()
                } else {
                    persistent_config_setter_method(cli_value, persistent_config).unwrap_or_else(
                        |e| {
                            panic!(
                                "{}: setting value in the database failed due to: {:?}",
                                parameter_name, e
                            )
                        },
                    )
                }
                cli_value
            }
            (None, pc_result) => {
                pc_result.map_err(|e| e.into_configurator_error(parameter_name))?
            }
        },
    )
}

fn configure_single_parameter_with_checking_overflow<S, T, C1, C2>(
    multi_config: &MultiConfig,
    parameter_name: &str,
    persistent_config: &mut dyn PersistentConfiguration,
    persistent_config_getter_method: &C1,
    persistent_config_setter_method: &mut C2,
) -> Result<S, ConfiguratorError>
where
    S: std::convert::TryFrom<T>,
    T: std::str::FromStr + PartialEq + Display + Copy,
    C1: Fn(&dyn PersistentConfiguration) -> Result<T, PersistentConfigError> + ?Sized,
    C2: FnMut(T, &mut dyn PersistentConfiguration) -> Result<(), PersistentConfigError> + ?Sized,
    <T as std::str::FromStr>::Err: std::fmt::Display,
    <S as std::convert::TryFrom<T>>::Error: std::fmt::Display,
{
    let fetched_value = configure_single_parameter::<T, C1, C2>(
        multi_config,
        parameter_name,
        persistent_config,
        persistent_config_getter_method,
        persistent_config_setter_method,
    )?;
    S::try_from(fetched_value).map_err(|e| {
        ConfiguratorError::required(
            parameter_name,
            format!("{}; value: {}", e, fetched_value).as_str(),
        )
    })
}

fn get_db_password(
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

fn is_user_specified(multi_config: &MultiConfig, parameter: &str) -> bool {
    multi_config.occurrences_of(parameter) > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::app_node;
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use crate::db_config::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::db_config::persistent_configuration::PersistentConfigError::NotPresent;
    use crate::db_config::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::cryptde::{PlainData, PublicKey};
    use crate::sub_lib::utils::make_new_test_multi_config;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::unshared_test_utils::{
        configure_default_persistent_config, default_persistent_config_just_accountant_config,
        make_persistent_config_real_with_config_dao_null, make_simplified_multi_config,
    };
    use crate::test_utils::{main_cryptde, unshared_test_utils, ArgsBuilder};
    use masq_lib::constants::DEFAULT_GAS_PRICE;
    use masq_lib::multi_config::{CommandLineVcl, NameValueVclArg, VclArg, VirtualCommandLine};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::running_test;
    use std::path::PathBuf;
    use std::str::FromStr;
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

        let result = get_wallets(
            &multi_config,
            &mut persistent_config,
            &mut bootstrapper_config,
        )
        .err()
        .unwrap();

        assert_eq!(result, ConfiguratorError::required("consuming-private-key, earning-wallet", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information"))
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

        let result = get_wallets(
            &multi_config,
            &mut persistent_config,
            &mut bootstrapper_config,
        )
        .err()
        .unwrap();

        assert_eq! (result, ConfiguratorError::required("consuming-private-key", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information"))
    }

    #[test]
    fn convert_ci_configs_handles_blockchain_mismatch() {
        let multi_config = make_simplified_multi_config([
            "--neighbors",
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@12.23.34.45:5678",
            "--chain",
            DEFAULT_CHAIN.rec().literal_identifier,
        ]);

        let result = convert_ci_configs(&multi_config).err().unwrap();

        assert_eq!(
            result,
            ConfiguratorError::required(
                "neighbors",
                "Mismatched chains. You are requiring access to 'eth-mainnet' (masq://eth-mainnet:<public key>@<node address>) with descriptor belonging to 'eth-ropsten'"
            )
        )
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001),
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001),
            &mut BootstrapperConfig::new(),
        );

        let node_addr = match result {
            Ok(NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(node_addr, _, _),
            }) => node_addr,
            x => panic!("Wasn't expecting {:?}", x),
        };
        assert_eq!(node_addr.ip_addr(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001),
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001).check_password_result(Ok(false)),
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001),
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001),
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001).check_password_result(Ok(false)),
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

        let result = make_neighborhood_config(
            &ParseArgsConfigurationDaoNull {},
            &multi_config,
            &mut configure_default_persistent_config(0b0000_0001).check_password_result(Ok(false)),
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
    fn parse_args_configuration_dao_real_get_past_neighbors_handles_good_password_but_no_past_neighbors(
    ) {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut persistent_config = configure_default_persistent_config(0b0000_0001);
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());
        let subject = ParseArgsConfigurationDaoReal {};

        let result = subject
            .get_past_neighbors(
                &multi_config,
                &mut persistent_config,
                &mut unprivileged_config,
            )
            .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn parse_args_configuration_dao_real_get_past_neighbors_handles_unavailable_password() {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut persistent_config =
            configure_default_persistent_config(0b0000_0001).check_password_result(Ok(true));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());
        let subject = ParseArgsConfigurationDaoReal {};

        let result = subject
            .get_past_neighbors(
                &multi_config,
                &mut persistent_config,
                &mut unprivileged_config,
            )
            .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn parse_args_configuration_dao_real_get_past_neighbors_handles_non_password_error() {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut persistent_config = PersistentConfigurationMock::new()
            .check_password_result(Ok(false))
            .past_neighbors_result(Err(PersistentConfigError::NotPresent));
        let mut unprivileged_config = BootstrapperConfig::new();
        unprivileged_config.db_password_opt = Some("password".to_string());
        let subject = ParseArgsConfigurationDaoReal {};

        let result = subject.get_past_neighbors(
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
    fn parse_args_configuration_dao_null_get_past_neighbors_does_nothing() {
        //this scenario is slightly adapted from the reality; we would've been using PersistentConfigurationReal
        //with ConfigDaoNull but it wouldn't have necessarily panicked if its method called so we use PersistentConfigMock
        //which can provide us with a reaction like so
        running_test();
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config = PersistentConfigurationMock::new();
        let mut unprivileged_config = BootstrapperConfig::new();
        let subject = ParseArgsConfigurationDaoNull {};

        let result = subject.get_past_neighbors(
            &multi_config,
            &mut persistent_config,
            &mut unprivileged_config,
        );

        assert_eq!(result, Ok(vec![]));
        //Nothing panicked so we could not call real persistent config's methods.
    }

    #[test]
    fn set_db_password_at_first_mention_handles_existing_password() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(false));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

        assert_eq!(result, Ok(false));
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![None])
    }

    #[test]
    fn set_db_password_at_first_mention_sets_password_correctly() {
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .check_password_result(Ok(true))
            .change_password_params(&change_password_params_arc)
            .change_password_result(Ok(()));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

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
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .check_password_params(&check_password_params_arc)
            .check_password_result(Err(PersistentConfigError::NotPresent));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("db-password"))
        );
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(*check_password_params, vec![None])
    }

    #[test]
    fn set_db_password_at_first_mention_handles_password_set_error() {
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .check_password_result(Ok(true))
            .change_password_params(&change_password_params_arc)
            .change_password_result(Err(PersistentConfigError::NotPresent));

        let result = set_db_password_at_first_mention("password", &mut persistent_config);

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

    #[test]
    fn get_db_password_shortcuts_if_its_already_gotten() {
        running_test();
        let multi_config = unshared_test_utils::make_simplified_multi_config([]);
        let mut config = BootstrapperConfig::new();
        let mut persistent_config =
            configure_default_persistent_config(0b0000_0001).check_password_result(Ok(false));
        config.db_password_opt = Some("password".to_string());

        let result = get_db_password(&multi_config, &mut config, &mut persistent_config);

        assert_eq!(result, Ok(Some("password".to_string())));
    }

    #[test]
    fn get_db_password_doesnt_bother_if_database_has_no_password_yet() {
        running_test();
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();
        let mut config = BootstrapperConfig::new();
        let mut persistent_config =
            configure_default_persistent_config(0b0000_0001).check_password_result(Ok(true));

        let result = get_db_password(&multi_config, &mut config, &mut persistent_config);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn get_db_password_handles_database_write_error() {
        running_test();
        let args = ["--db-password", "password"];
        let multi_config = unshared_test_utils::make_simplified_multi_config(args);
        let mut config = BootstrapperConfig::new();
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .check_password_result(Ok(true))
            .check_password_result(Ok(true))
            .check_password_result(Ok(true))
            .change_password_result(Err(PersistentConfigError::NotPresent));

        let result = get_db_password(&multi_config, &mut config, &mut persistent_config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("db-password"))
        );
    }

    #[test]
    fn convert_ci_configs_handles_leftover_whitespaces_between_descriptors_and_commas() {
        let multi_config = make_simplified_multi_config([
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

        let result = convert_ci_configs(&multi_config);

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
        let multi_config = make_simplified_multi_config(["--neighbors", "ooga,booga"]);

        let result = convert_ci_configs(&multi_config).err();

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
        let multi_config = make_simplified_multi_config(["--neighbors", &descriptor]);

        let result = convert_ci_configs(&multi_config);

        assert_eq!(result,Err(ConfiguratorError::new(vec![ParamError::new("neighbors", &format!("Neighbors supplied without ip addresses and ports are not valid: '{}<N/A>:<N/A>",&descriptor[..descriptor.len()-1]))])));
    }

    #[test]
    fn convert_ci_configs_complains_about_descriptor_without_node_address_when_test_chain_required()
    {
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-ropsten",
            "--neighbors",
            "masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@:",
        ]);

        let result = convert_ci_configs(&multi_config);

        assert_eq!(result,Err(ConfiguratorError::new(vec![ParamError::new("neighbors", "Neighbors supplied without ip addresses and ports are not valid: 'masq://eth-ropsten:abJ5XvhVbmVyGejkYUkmftF09pmGZGKg_PzRNnWQxFw@<N/A>:<N/A>")])))
    }

    #[test]
    fn configure_zero_hop_with_neighbors_supplied() {
        running_test();
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let mut config = BootstrapperConfig::new();
        let mut persistent_config = configure_default_persistent_config(0b0000_1111)
            .set_past_neighbors_params(&set_past_neighbors_params_arc)
            .set_past_neighbors_result(Ok(()));
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-ropsten",
            "--neighbors",
            "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345",
            "--db-password",
            "password",
            "--neighborhood-mode",
            "zero-hop",
            "--fake-public-key",
            "booga",
        ]);
        let subject = ParseArgsConfigurationDaoReal {};

        let _ = subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(
            config.neighborhood_config,
            NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop
            }
        );
        let set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        assert_eq!(
            *set_past_neighbors_params,
            vec![(
                Some(vec![NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345"
                ))
                .unwrap()]),
                "password".to_string()
            )]
        )
    }

    #[test]
    fn setting_zero_hop_neighbors_is_ignored_if_no_neighbors_supplied() {
        running_test();
        let set_past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let mut config = BootstrapperConfig::new();
        let mut persistent_config = configure_default_persistent_config(0b0000_1111)
            .set_past_neighbors_params(&set_past_neighbors_params_arc);
        let multi_config = make_simplified_multi_config([
            "--chain",
            "eth-ropsten",
            "--neighborhood-mode",
            "zero-hop",
        ]);
        let subject = ParseArgsConfigurationDaoReal {};

        let _ = subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(
            config.neighborhood_config,
            NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop
            }
        );
        let set_past_neighbors_params = set_past_neighbors_params_arc.lock().unwrap();
        assert!(set_past_neighbors_params.is_empty())
    }

    #[test]
    fn configure_zero_hop_with_neighbors_but_no_password() {
        running_test();
        let mut persistent_config = PersistentConfigurationMock::new();
        //no results prepared for set_past_neighbors() and no panic so it was not called
        let descriptor_list = vec![NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345",
        ))
        .unwrap()];

        let result =
            zero_hop_neighbors_configuration(None, descriptor_list, &mut persistent_config);

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighbors",
                "Cannot proceed without a password"
            ))
        );
    }

    #[test]
    fn configure_zero_hop_with_neighbors_but_setting_values_failed() {
        running_test();
        let mut persistent_config = PersistentConfigurationMock::new().set_past_neighbors_result(
            Err(PersistentConfigError::DatabaseError("Oh yeah".to_string())),
        );
        let descriptor_list = vec![NodeDescriptor::try_from((
            main_cryptde(),
            "masq://eth-ropsten:UJNoZW5p-PDVqEjpr3b_8jZ_93yPG8i5dOAgE1bhK_A@2.3.4.5:2345",
        ))
        .unwrap()];

        let result = zero_hop_neighbors_configuration(
            Some("password".to_string()),
            descriptor_list,
            &mut persistent_config,
        );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "neighbors",
                "DatabaseError(\"Oh yeah\")"
            ))
        );
    }

    #[test]
    fn unprivileged_parse_args_creates_configurations() {
        running_test();
        let home_dir = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "unprivileged_parse_args_creates_configurations",
        );
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir.clone(), true, MigratorConfig::test_default())
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
            .param("--mapping-protocol", "pcp")
            .param("--real-user", "999:999:/home/booga");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
        let subject = ParseArgsConfigurationDaoNull {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test logger"),
            )
            .unwrap();

        assert_eq!(
            value_m!(multi_config, "config-file", PathBuf),
            Some(PathBuf::from("specified_config.toml")),
        );
        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url_opt,
            Some("http://127.0.0.1:8545".to_string())
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
            config.consuming_wallet_opt,
            Some(Wallet::from(
                Bip32ECKeyProvider::from_raw_secret(consuming_private_key.as_slice()).unwrap()
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
        assert_eq!(config.mapping_protocol_opt, Some(AutomapProtocol::Pcp));
    }

    #[test]
    fn unprivileged_parse_args_creates_configuration_with_defaults() {
        running_test();
        let args = ArgsBuilder::new();
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
        let mut persistent_config =
            configure_default_persistent_config(0b0000_1111).check_password_result(Ok(false));
        let subject = ParseArgsConfigurationDaoNull {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test logger"),
            )
            .unwrap();

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
            IpAddr::from_str("0.0.0.0").unwrap(),
        );
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone(),);
        assert_eq!(config.consuming_wallet_opt, None);
        assert_eq!(config.mapping_protocol_opt, None);
    }

    #[test]
    fn unprivileged_parse_args_with_neighbor_and_mapping_protocol_in_database_but_not_command_line()
    {
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
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_configuration = {
            let config = make_persistent_config(
                None,
                Some("password"),
                None,
                None,
                None,
                Some(
                    "masq://eth-ropsten:AQIDBA@1.2.3.4:1234,masq://eth-ropsten:AgMEBQ@2.3.4.5:2345",
                ),
                None,
                None,
                None,
                None,
            )
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .past_neighbors_params(&past_neighbors_params_arc)
            .blockchain_service_url_result(Ok(None));
            default_persistent_config_just_accountant_config(config)
        };
        let subject = ParseArgsConfigurationDaoReal {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test logger"),
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
        assert_eq!(config.mapping_protocol_opt, Some(AutomapProtocol::Pcp));
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(*set_mapping_protocol_params, vec![]);
    }

    #[test]
    fn unprivileged_parse_args_with_blockchain_service_in_database_but_not_command_line() {
        running_test();
        let args = ArgsBuilder::new().param("--neighborhood-mode", "zero-hop");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
        let mut persistent_configuration = {
            let config =
                make_persistent_config(None, None, None, None, None, None, None, None, None, None)
                    .blockchain_service_url_result(Ok(Some("https://infura.io/ID".to_string())));
            default_persistent_config_just_accountant_config(config)
        };
        let subject = ParseArgsConfigurationDaoNull {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        assert_eq!(
            config.blockchain_bridge_config.blockchain_service_url_opt,
            Some("https://infura.io/ID".to_string())
        );
    }

    #[test]
    fn unprivileged_parse_args_with_mapping_protocol_both_on_command_line_and_in_database() {
        running_test();
        let args = ArgsBuilder::new().param("--mapping-protocol", "pmp");
        let mut config = BootstrapperConfig::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_node(), vcls).unwrap();
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(0b0000_1101)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pcp)))
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));
        let subject = ParseArgsConfigurationDaoNull {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_config,
                &Logger::new("test logger"),
            )
            .unwrap();

        assert_eq!(config.mapping_protocol_opt, Some(AutomapProtocol::Pmp));
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(
            *set_mapping_protocol_params,
            vec![Some(AutomapProtocol::Pmp)]
        );
    }

    #[test]
    fn unprivileged_parse_args_consuming_private_key_happy_path() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
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
        let subject = ParseArgsConfigurationDaoNull {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut configure_default_persistent_config(0b0000_1111),
                &Logger::new("test logger"),
            )
            .unwrap();

        assert!(config.consuming_wallet_opt.is_some());
        assert_eq!(
            format!("{}", config.consuming_wallet_opt.unwrap()),
            "0x8e4d2317e56c8fd1fc9f13ba2aa62df1c5a542a7".to_string()
        );
    }

    #[test]
    fn unprivileged_parse_args_configures_accountant_with_values_from_command_line_different_from_those_in_database(
    ) {
        running_test();
        let set_pending_payment_scan_interval_params_arc = Arc::new(Mutex::new(vec![]));
        let set_payable_scan_interval_params_arc = Arc::new(Mutex::new(vec![]));
        let set_receivable_scan_interval_params_arc = Arc::new(Mutex::new(vec![]));
        let set_payment_grace_before_ban_params_arc = Arc::new(Mutex::new(vec![]));
        let set_payment_suggested_after_params_arc = Arc::new(Mutex::new(vec![]));
        let set_permanent_debt_allowed_params_arc = Arc::new(Mutex::new(vec![]));
        let set_balance_to_decrease_from_params_arc = Arc::new(Mutex::new(vec![]));
        let set_unban_when_balance_below_params_arc = Arc::new(Mutex::new(vec![]));
        let set_balance_decreases_for_params_arc = Arc::new(Mutex::new(vec![]));
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "unprivileged_parse_args_configures_accountant_with_values_from_command_line_different_from_those_in_database",
        );
        let args = [
            "--ip",
            "1.2.3.4",
            "--data-directory",
            home_directory.to_str().unwrap(),
            "--pending-payment-scan-interval",
            "180",
            "--payable-scan-interval",
            "150",
            "--receivable-scan-interval",
            "130",
            "--payment-grace-before-ban",
            "1000",
            "--payment-suggested-after",
            "1000",
            "--permanent-debt-allowed",
            "20000",
            "--balance-to-decrease-from",
            "100000",
            "--unban-when-balance-below",
            "20000",
            "--balance-decreases-for",
            "1000",
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration = configure_default_persistent_config(0b0000_1011)
            .pending_payment_scan_interval_result(Ok(100))
            .payable_scan_interval_result(Ok(101))
            .receivable_scan_interval_result(Ok(102))
            .payment_grace_before_ban_sec_result(Ok(900))
            .payment_suggested_after_sec_result(Ok(900))
            .permanent_debt_allowed_gwei_result(Ok(15000))
            .balance_to_decrease_from_gwei_result(Ok(80000))
            .unban_when_balance_below_gwei_result(Ok(15000))
            .balance_decreases_for_sec_result(Ok(800))
            .set_pending_payment_scan_interval_params(&set_pending_payment_scan_interval_params_arc)
            .set_pending_payment_scan_interval_result(Ok(()))
            .set_payable_scan_interval_params(&set_payable_scan_interval_params_arc)
            .set_payable_scan_interval_result(Ok(()))
            .set_receivable_scan_interval_params(&set_receivable_scan_interval_params_arc)
            .set_receivable_scan_interval_result(Ok(()))
            .set_payment_grace_before_ban_sec_params(&set_payment_grace_before_ban_params_arc)
            .set_payment_grace_before_ban_sec_result(Ok(()))
            .set_payment_suggested_after_sec_params(&set_payment_suggested_after_params_arc)
            .set_payment_suggested_after_sec_result(Ok(()))
            .set_permanent_debt_allowed_gwei_params(&set_permanent_debt_allowed_params_arc)
            .set_permanent_debt_allowed_gwei_result(Ok(()))
            .set_balance_to_decrease_from_gwei_params(&set_balance_to_decrease_from_params_arc)
            .set_balance_to_decrease_from_gwei_result(Ok(()))
            .set_unban_when_balance_below_gwei_params(&set_unban_when_balance_below_params_arc)
            .set_unban_when_balance_below_gwei_result(Ok(()))
            .set_balance_decreases_for_sec_params(&set_balance_decreases_for_params_arc)
            .set_balance_decreases_for_sec_result(Ok(()));
        let subject = ParseArgsConfigurationDaoNull {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        let actual_rate_pack = config.accountant_config;
        let expected_rate_pack = AccountantConfig {
            pending_payment_scan_interval_opt: Some(Duration::from_secs(180)),
            payable_scan_interval_opt: Some(Duration::from_secs(150)),
            receivable_scan_interval_opt: Some(Duration::from_secs(130)),
            payment_curves_opt: Some(PaymentCurves {
                payment_suggested_after_sec: 1000,
                payment_grace_before_ban_sec: 1000,
                permanent_debt_allowed_gwei: 20000,
                balance_to_decrease_from_gwei: 100000,
                balance_decreases_for_sec: 1000,
                unban_when_balance_below_gwei: 20000,
            }),
        };
        assert_eq!(actual_rate_pack, expected_rate_pack);
        let set_pending_payment_scan_interval_params =
            set_pending_payment_scan_interval_params_arc.lock().unwrap();
        assert_eq!(*set_pending_payment_scan_interval_params, vec![180]);
        let set_payable_scan_interval_params = set_payable_scan_interval_params_arc.lock().unwrap();
        assert_eq!(*set_payable_scan_interval_params, vec![150]);
        let set_receivable_scan_interval_params =
            set_receivable_scan_interval_params_arc.lock().unwrap();
        assert_eq!(*set_receivable_scan_interval_params, vec![130]);
        let set_payment_grace_before_ban_params =
            set_payment_grace_before_ban_params_arc.lock().unwrap();
        assert_eq!(*set_payment_grace_before_ban_params, vec![1000]);
        let set_payment_suggested_after_params =
            set_payment_suggested_after_params_arc.lock().unwrap();
        assert_eq!(*set_payment_suggested_after_params, vec![1000]);
        let set_permanent_debt_allowed_params =
            set_permanent_debt_allowed_params_arc.lock().unwrap();
        assert_eq!(*set_permanent_debt_allowed_params, vec![20000]);
        let set_balance_to_decrease_from_params =
            set_balance_to_decrease_from_params_arc.lock().unwrap();
        assert_eq!(*set_balance_to_decrease_from_params, vec![100000]);
        let set_unban_when_balance_below_params =
            set_unban_when_balance_below_params_arc.lock().unwrap();
        assert_eq!(*set_unban_when_balance_below_params, vec![20000]);
        let set_balance_decreases_for_params = set_balance_decreases_for_params_arc.lock().unwrap();
        assert_eq!(*set_balance_decreases_for_params, vec![1000])
    }

    #[test]
    fn unprivileged_parse_args_with_invalid_consuming_wallet_private_key_reacts_correctly() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
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
    fn unprivileged_parse_args_configures_rate_pack_with_values_from_command_line_different_from_what_is_in_the_database(
    ) {
        running_test();
        let set_routing_byte_rate_params_arc = Arc::new(Mutex::new(vec![]));
        let set_routing_service_rate_params_arc = Arc::new(Mutex::new(vec![]));
        let set_exit_byte_rate_params_arc = Arc::new(Mutex::new(vec![]));
        let set_exit_service_rate_params_arc = Arc::new(Mutex::new(vec![]));
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "unprivileged_parse_args_configures_rate_pack_with_values_from_command_line_different_from_what_is_in_the_database",
        );
        let args = [
            "--ip",
            "1.2.3.4",
            "--blockchain-service-url",
            "some.service.com",
            "--gas-price",
            "170",
            "--data-directory",
            home_directory.to_str().unwrap(),
            "--routing-byte-rate",
            "2",
            "--routing-service-rate",
            "3",
            "--exit-byte-rate",
            "4",
            "--exit-service-rate",
            "5",
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration = configure_default_persistent_config(0b0000_0111)
            .routing_byte_rate_result(Ok(10))
            .routing_service_rate_result(Ok(11))
            .exit_byte_rate_result(Ok(12))
            .exit_service_rate_result(Ok(13))
            .set_routing_byte_rate_params(&set_routing_byte_rate_params_arc)
            .set_routing_byte_rate_result(Ok(()))
            .set_routing_service_rate_params(&set_routing_service_rate_params_arc)
            .set_routing_service_rate_result(Ok(()))
            .set_exit_byte_rate_params(&set_exit_byte_rate_params_arc)
            .set_exit_byte_rate_result(Ok(()))
            .set_exit_service_rate_params(&set_exit_service_rate_params_arc)
            .set_exit_service_rate_result(Ok(()));
        //no prepared results for the getter methods, that is they're uncalled
        let subject = ParseArgsConfigurationDaoNull {};

        subject
            .unprivileged_parse_args(
                &multi_config,
                &mut config,
                &mut persistent_configuration,
                &Logger::new("test"),
            )
            .unwrap();

        let actual_rate_pack = config.rate_pack_opt.take().unwrap();
        let expected_rate_pack = RatePack {
            routing_byte_rate: 2,
            routing_service_rate: 3,
            exit_byte_rate: 4,
            exit_service_rate: 5,
        };
        assert_eq!(actual_rate_pack, expected_rate_pack);
        let set_routing_byte_rate_params = set_routing_byte_rate_params_arc.lock().unwrap();
        assert_eq!(*set_routing_byte_rate_params, vec![2]);
        let set_routing_service_rate_params = set_routing_service_rate_params_arc.lock().unwrap();
        assert_eq!(*set_routing_service_rate_params, vec![3]);
        let set_exit_byte_rate_params = set_exit_byte_rate_params_arc.lock().unwrap();
        assert_eq!(*set_exit_byte_rate_params, vec![4]);
        let set_exit_service_rate_params = set_exit_service_rate_params_arc.lock().unwrap();
        assert_eq!(*set_exit_service_rate_params, vec![5])
    }

    #[test]
    fn get_wallets_with_brand_new_database_establishes_default_earning_wallet_without_requiring_password(
    ) {
        running_test();
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config =
            make_persistent_config(None, None, None, None, None, None, None, None, None, None);
        let mut config = BootstrapperConfig::new();

        get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(config.consuming_wallet_opt, None);
        assert_eq!(config.earning_wallet, DEFAULT_EARNING_WALLET.clone());
    }

    #[test]
    fn get_wallets_handles_failure_of_mnemonic_seed_exists() {
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_from_address_result(Ok(None))
            .mnemonic_seed_exists_result(Err(PersistentConfigError::NotPresent));

        let result = get_wallets(
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
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_from_address_result(Ok(None))
            .mnemonic_seed_exists_result(Ok(true))
            .consuming_wallet_derivation_path_result(Err(PersistentConfigError::NotPresent));
        let mut config = BootstrapperConfig::new();
        config.db_password_opt = Some("password".to_string());

        let result = get_wallets(&multi_config, &mut persistent_config, &mut config);

        assert_eq!(
            result,
            Err(PersistentConfigError::NotPresent.into_configurator_error("consuming-private-key"))
        );
    }

    #[test]
    fn earning_wallet_address_different_from_database() {
        running_test();
        let args = [
            "--earning-wallet",
            "0x0123456789012345678901234567890123456789",
        ];
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(
            None,
            None,
            None,
            Some("0x9876543210987654321098765432109876543210"),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        let result = get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq! (result, Some (ConfiguratorError::new (vec![
            ParamError::new ("earning-wallet", "Cannot change to an address (0x0123456789012345678901234567890123456789) different from that previously set (0x9876543210987654321098765432109876543210)")
        ])));
    }

    #[test]
    fn earning_wallet_address_matches_database() {
        running_test();
        let args = [
            "--earning-wallet",
            "0xb00fa567890123456789012345678901234B00FA",
        ];
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config(
            None,
            None,
            None,
            Some("0xB00FA567890123456789012345678901234b00fa"),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

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
            "--db-password",
            "password",
            "--consuming-private-key",
            consuming_private_key_hex,
        ];
        let multi_config = make_simplified_multi_config(args);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        let result = get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq! (result, Some (ConfiguratorError::new (vec![
            ParamError::new ("consuming-private-key", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information")
        ])));
    }

    #[test]
    fn earning_wallet_address_plus_mnemonic_seed() {
        running_test();
        let args = [
            "--db-password",
            "password",
            "--earning-wallet",
            "0xcafedeadbeefbabefacecafedeadbeefbabeface",
        ];
        let multi_config = make_simplified_multi_config(args);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut config = BootstrapperConfig::new();

        let result = get_wallets(&multi_config, &mut persistent_config, &mut config).err();

        assert_eq! (result, Some (ConfiguratorError::new (vec![
            ParamError::new ("earning-wallet", "Cannot use --consuming-private-key or --earning-wallet when database contains wallet information")
        ])));
    }

    #[test]
    fn consuming_wallet_derivation_path_plus_earning_wallet_address_plus_mnemonic_seed() {
        running_test();
        let args = ["--db-password", "password"];
        let multi_config = make_simplified_multi_config(args);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            Some("password"),
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .check_password_result(Ok(false));
        let mut config = BootstrapperConfig::new();

        get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        let mnemonic_seed = make_mnemonic_seed(mnemonic_seed_prefix);
        let expected_consuming_wallet = Wallet::from(
            Bip32ECKeyProvider::try_from((mnemonic_seed.as_ref(), "m/44'/60'/1'/2/3")).unwrap(),
        );
        assert_eq!(config.consuming_wallet_opt, Some(expected_consuming_wallet));
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap()
        );
    }

    #[test]
    fn consuming_wallet_derivation_path_plus_mnemonic_seed_with_no_db_password_parameter() {
        running_test();
        let multi_config = make_simplified_multi_config([]);
        let mnemonic_seed_prefix = "mnemonic_seed";
        let mut persistent_config = make_persistent_config(
            Some(mnemonic_seed_prefix),
            None,
            Some("m/44'/60'/1'/2/3"),
            Some("0xcafedeadbeefbabefacecafedeadbeefbabeface"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .check_password_result(Ok(false));
        let mut config = BootstrapperConfig::new();

        get_wallets(&multi_config, &mut persistent_config, &mut config).unwrap();

        assert_eq!(config.consuming_wallet_opt, None);
        assert_eq!(
            config.earning_wallet,
            Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap()
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
    fn get_consuming_wallet_opt_from_derivation_path_handles_bad_password() {
        running_test();
        let persistent_config = PersistentConfigurationMock::new()
            .consuming_wallet_derivation_path_result(Ok(Some("m/44'/60'/1'/2/3".to_string())))
            .mnemonic_seed_result(Err(PersistentConfigError::PasswordError));

        let result =
            get_consuming_wallet_opt_from_derivation_path(&persistent_config, "bad password")
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

        let result = get_earning_wallet_from_address(&multi_config, &persistent_config)
            .err()
            .unwrap();

        assert_eq! (result, ConfiguratorError::required("earning-wallet", "Cannot change to an address (0x0123456789012345678901234567890123456789) different from that previously set (0x9876543210987654321098765432109876543210)"))
    }

    #[test]
    fn configure_single_parameter_with_overflow_check_handles_overflow() {
        let multi_config = make_simplified_multi_config([]);
        let mut persistent_config =
            PersistentConfigurationMock::default().exit_byte_rate_result(Ok(u64::MAX));

        let result: Result<i64, ConfiguratorError> =
            configure_single_parameter_with_checking_overflow(
                &multi_config,
                "exit-byte-rate",
                &mut persistent_config,
                &|persistent_config: &dyn PersistentConfiguration| {
                    persistent_config.exit_byte_rate()
                },
                &mut |rate, persistent_config: &mut dyn PersistentConfiguration| {
                    persistent_config.set_exit_byte_rate(rate)
                },
            );

        assert_eq!(
            result,
            Err(ConfiguratorError::required(
                "exit-byte-rate",
                "out of range integral type conversion attempted; value: 18446744073709551615"
            ))
        );
    }

    #[test]
    fn configure_rate_pack_from_database() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "configure_rate_pack_from_database",
        );
        let args = [
            "--ip",
            "1.2.3.4",
            "--blockchain-service-url",
            "some.service.com",
            "--gas-price",
            "170",
            "--data-directory",
            home_directory.to_str().unwrap(),
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_configuration = PersistentConfigurationMock::new()
            .earning_wallet_from_address_result(Ok(None))
            .consuming_wallet_derivation_path_result(Ok(None))
            .mnemonic_seed_result(Ok(None))
            .mnemonic_seed_exists_result(Ok(false))
            .mapping_protocol_result(Ok(None))
            .routing_byte_rate_result(Ok(8))
            .routing_service_rate_result(Ok(7))
            .exit_byte_rate_result(Ok(10))
            .exit_service_rate_result(Ok(11));

        configure_rate_pack(&multi_config, &mut config, &mut persistent_configuration).unwrap();

        let actual_rate_pack = config.rate_pack_opt.take().unwrap();
        let expected_rate_pack = RatePack {
            routing_byte_rate: 8,
            routing_service_rate: 7,
            exit_byte_rate: 10,
            exit_service_rate: 11,
        };
        assert_eq!(actual_rate_pack, expected_rate_pack)
    }

    #[test]
    fn configure_rate_pack_command_line_absent_null_config_dao_so_all_defaults() {
        running_test();
        let home_directory = ensure_node_home_directory_exists(
            "unprivileged_parse_args_configuration",
            "configure_rate_pack_command_line_absent_null_config_dao_so_all_defaults",
        );
        let args = [
            "--ip",
            "1.2.3.4",
            "--blockchain-service-url",
            "some.service.com",
            "--gas-price",
            "170",
            "--data-directory",
            home_directory.to_str().unwrap(),
        ];
        let mut config = BootstrapperConfig::new();
        let multi_config = make_simplified_multi_config(args);
        let mut persistent_config = make_persistent_config_real_with_config_dao_null();

        configure_rate_pack(&multi_config, &mut config, &mut persistent_config).unwrap();

        let actual_rate_pack = config.rate_pack_opt.take().unwrap();
        let expected_rate_pack = RatePack {
            routing_byte_rate: DEFAULT_RATE_PACK.routing_byte_rate,
            routing_service_rate: DEFAULT_RATE_PACK.routing_service_rate,
            exit_byte_rate: DEFAULT_RATE_PACK.exit_byte_rate,
            exit_service_rate: DEFAULT_RATE_PACK.exit_service_rate,
        };
        assert_eq!(actual_rate_pack, expected_rate_pack)
    }

    #[test]
    fn compute_mapping_protocol_returns_saved_value_if_nothing_supplied() {
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(ArgsBuilder::new().into()))],
        )
        .unwrap();
        let logger = Logger::new("test");
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pmp)));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Pmp));
        // No result provided for .set_mapping_protocol; if it's called, the panic will fail this test
    }

    #[test]
    fn compute_mapping_protocol_saves_computed_value_if_different() {
        let multi_config = make_new_test_multi_config(
            &app_node(),
            vec![Box::new(CommandLineVcl::new(
                ArgsBuilder::new()
                    .param("--mapping-protocol", "IGDP")
                    .into(),
            ))],
        )
        .unwrap();
        let logger = Logger::new("test");
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pmp)))
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Igdp));
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(
            *set_mapping_protocol_params,
            vec![Some(AutomapProtocol::Igdp)]
        );
    }

    #[test]
    fn compute_mapping_protocol_blanks_database_if_command_line_with_missing_value() {
        let multi_config = make_simplified_multi_config(["--mapping-protocol"]);
        let logger = Logger::new("test");
        let set_mapping_protocol_params_arc = Arc::new(Mutex::new(vec![]));
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pmp)))
            .set_mapping_protocol_params(&set_mapping_protocol_params_arc)
            .set_mapping_protocol_result(Ok(()));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, None);
        let set_mapping_protocol_params = set_mapping_protocol_params_arc.lock().unwrap();
        assert_eq!(*set_mapping_protocol_params, vec![None]);
    }

    #[test]
    fn compute_mapping_protocol_does_not_resave_entry_if_no_change() {
        let multi_config = make_simplified_multi_config(["--mapping-protocol", "igdp"]);
        let logger = Logger::new("test");
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Igdp)));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Igdp));
        // No result provided for .set_mapping_protocol; if it's called, the panic will fail this test
    }

    #[test]
    fn compute_mapping_protocol_logs_and_uses_none_if_saved_mapping_protocol_cannot_be_read() {
        init_test_logging();
        let multi_config = make_simplified_multi_config([]);
        let logger = Logger::new("BAD_MP_READ");
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .mapping_protocol_result(Err(PersistentConfigError::NotPresent));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, None);
        // No result provided for .set_mapping_protocol; if it's called, the panic will fail this test
        TestLogHandler::new().exists_log_containing(
            "WARN: BAD_MP_READ: Could not read mapping protocol from database: NotPresent",
        );
    }

    #[test]
    fn compute_mapping_protocol_logs_and_moves_on_if_mapping_protocol_cannot_be_saved() {
        init_test_logging();
        let multi_config = make_simplified_multi_config(["--mapping-protocol", "IGDP"]);
        let logger = Logger::new("BAD_MP_WRITE");
        let mut persistent_config = configure_default_persistent_config(0b0000_0001)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pcp)))
            .set_mapping_protocol_result(Err(PersistentConfigError::NotPresent));

        let result = compute_mapping_protocol_opt(&multi_config, &mut persistent_config, &logger);

        assert_eq!(result, Some(AutomapProtocol::Igdp));
        TestLogHandler::new().exists_log_containing(
            "WARN: BAD_MP_WRITE: Could not save mapping protocol to database: NotPresent",
        );
    }

    #[test]
    fn get_public_ip_returns_sentinel_if_multiconfig_provides_none() {
        let multi_config = make_new_test_multi_config(&app_node(), vec![]).unwrap();

        let result = get_public_ip(&multi_config);

        assert_eq!(result, Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }

    #[test]
    fn get_public_ip_uses_multi_config() {
        let args = ArgsBuilder::new().param("--ip", "4.3.2.1");
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_test_multi_config(&app_node(), vec![vcl]).unwrap();

        let result = get_public_ip(&multi_config);

        assert_eq!(result, Ok(IpAddr::from_str("4.3.2.1").unwrap()));
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

    fn make_persistent_config(
        mnemonic_seed_prefix_opt: Option<&str>,
        db_password_opt: Option<&str>,
        consuming_wallet_derivation_path_opt: Option<&str>,
        earning_wallet_address_opt: Option<&str>,
        gas_price_opt: Option<u64>,
        past_neighbors_opt: Option<&str>,
        routing_byte_rate_opt: Option<u64>,
        routing_service_rate_opt: Option<u64>,
        exit_byte_rate_opt: Option<u64>,
        exit_service_rate_opt: Option<u64>,
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
        let gas_price = gas_price_opt.unwrap_or(DEFAULT_GAS_PRICE);
        let past_neighbors_result = match (past_neighbors_opt, db_password_opt) {
            (Some(past_neighbors), Some(_)) => Ok(Some(
                past_neighbors
                    .split(",")
                    .map(|s| NodeDescriptor::try_from((main_cryptde(), s)).unwrap())
                    .collect::<Vec<NodeDescriptor>>(),
            )),
            _ => Ok(None),
        };
        let routing_byte_rate_result =
            routing_byte_rate_opt.unwrap_or(DEFAULT_RATE_PACK.routing_byte_rate);
        let routing_service_rate_result =
            routing_service_rate_opt.unwrap_or(DEFAULT_RATE_PACK.routing_service_rate);
        let exit_byte_rate_result = exit_byte_rate_opt.unwrap_or(DEFAULT_RATE_PACK.exit_byte_rate);
        let exit_service_rate_result =
            exit_service_rate_opt.unwrap_or(DEFAULT_RATE_PACK.exit_service_rate);
        PersistentConfigurationMock::new()
            .mnemonic_seed_result(mnemonic_seed_result)
            .mnemonic_seed_exists_result(mnemonic_seed_exists_result)
            .consuming_wallet_derivation_path_result(Ok(consuming_wallet_derivation_path_opt))
            .earning_wallet_from_address_result(Ok(earning_wallet_from_address_opt))
            .gas_price_result(Ok(gas_price))
            .past_neighbors_result(past_neighbors_result)
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pcp)))
            .routing_byte_rate_result(Ok(routing_byte_rate_result))
            .routing_service_rate_result(Ok(routing_service_rate_result))
            .exit_byte_rate_result(Ok(exit_byte_rate_result))
            .exit_service_rate_result(Ok(exit_service_rate_result))
    }
}
