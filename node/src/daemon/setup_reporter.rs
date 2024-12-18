// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::apps::app_head;
use crate::bootstrapper::BootstrapperConfig;
use crate::daemon::dns_inspector::dns_inspector_factory::{
    DnsInspectorFactory, DnsInspectorFactoryReal,
};
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, InitializationError};
use crate::db_config::config_dao_null::ConfigDaoNull;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::neighborhood::DEFAULT_MIN_HOPS;
use crate::node_configurator::node_configurator_standard::privileged_parse_args;
use crate::node_configurator::unprivileged_parse_args_configuration::{
    UnprivilegedParseArgsConfiguration, UnprivilegedParseArgsConfigurationDaoNull,
    UnprivilegedParseArgsConfigurationDaoReal,
};
use crate::node_configurator::{
    data_directory_from_context, determine_user_specific_data, DirsWrapper, DirsWrapperReal,
};
use crate::sub_lib::accountant::PaymentThresholds as PaymentThresholdsFromAccountant;
use crate::sub_lib::accountant::DEFAULT_SCAN_INTERVALS;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::neighborhood::{NeighborhoodMode as NeighborhoodModeEnum, DEFAULT_RATE_PACK};
use crate::sub_lib::utils::make_new_multi_config;
use crate::test_utils::main_cryptde;
use clap::{value_t, App};
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain as BlockChain;
use masq_lib::constants::DEFAULT_CHAIN;
use masq_lib::logger::Logger;
use masq_lib::messages::UiSetupResponseValueStatus::{Blank, Configured, Default, Required, Set};
use masq_lib::messages::{UiSetupRequestValue, UiSetupResponseValue, UiSetupResponseValueStatus};
use masq_lib::multi_config::{
    CommandLineVcl, ConfigFileVcl, EnvironmentVcl, MultiConfig, VirtualCommandLine,
};
use masq_lib::shared_schema::{data_directory_arg, shared_app, ConfiguratorError};
use masq_lib::utils::{
    add_chain_specific_directory, to_string, ExpectValue, DATA_DIRECTORY_DAEMON_HELP,
};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const CONSOLE_DIAGNOSTICS: bool = false;

const ARG_PAIRS_SENSITIVE_TO_SETUP_ERRS: &[ErrorSensitiveArgPair] = &[
    // If we have chain A and data directory X, and then an incoming_setup arrives with chain blanked out and data
    // directory Y, we'll preserve the blank chain, but resurrect data directory X. (I'm not sure this is correct;
    // perhaps if we're going to take advantage of a default chain, we should also use the default chain's data
    // directory. --Dan)
    ErrorSensitiveArgPair {
        blanked_arg: "chain",
        linked_arg: "data-directory",
    },
];

pub type SetupCluster = HashMap<String, UiSetupResponseValue>;

#[cfg(test)]
pub fn setup_cluster_from(input: Vec<(&str, &str, UiSetupResponseValueStatus)>) -> SetupCluster {
    input
        .into_iter()
        .map(|(k, v, s)| (k.to_string(), UiSetupResponseValue::new(k, v, s)))
        .collect::<SetupCluster>()
}

fn daemon_shared_app() -> App<'static, 'static> {
    shared_app(app_head()).arg(data_directory_arg(DATA_DIRECTORY_DAEMON_HELP.as_str()))
}

pub trait SetupReporter {
    fn get_modified_setup(
        &self,
        existing_setup: SetupCluster,
        incoming_setup: Vec<UiSetupRequestValue>,
    ) -> Result<SetupCluster, (SetupCluster, ConfiguratorError)>;
}

pub struct SetupReporterReal {
    dirs_wrapper: Box<dyn DirsWrapper>,
    logger: Logger,
}

impl SetupReporter for SetupReporterReal {
    fn get_modified_setup(
        &self,
        mut existing_setup: SetupCluster,
        incoming_setup: Vec<UiSetupRequestValue>,
    ) -> Result<SetupCluster, (SetupCluster, ConfiguratorError)> {
        let default_setup = Self::get_default_params();
        let mut blanked_out_former_values = HashMap::new();
        incoming_setup
            .iter()
            .filter(|v| v.value.is_none())
            .for_each(|v| {
                if let Some(former_value) = existing_setup.remove(&v.name) {
                    blanked_out_former_values.insert(v.name.clone(), former_value);
                };
            });
        let prevention_to_err_induced_setup_impairments =
            Self::prevent_err_induced_setup_impairments(
                &blanked_out_former_values,
                &existing_setup,
            );
        let mut incoming_setup = incoming_setup
            .into_iter()
            .filter(|v| v.value.is_some())
            .map(|v| {
                (
                    v.name.clone(),
                    UiSetupResponseValue::new(&v.name, &v.value.expect("Value disappeared!"), Set),
                )
            })
            .collect::<SetupCluster>();
        let all_but_configured =
            Self::combine_clusters(vec![&default_setup, &existing_setup, &incoming_setup]);
        eprintln_setup("DEFAULTS", &default_setup);
        eprintln_setup("EXISTING", &existing_setup);
        eprintln_setup("BLANKED-OUT FORMER VALUES", &blanked_out_former_values);
        eprintln_setup(
            "PREVENTION TO ERR INDUCED SETUP IMPAIRMENTS",
            &prevention_to_err_induced_setup_impairments,
        );
        eprintln_setup("INCOMING", &incoming_setup);
        eprintln_setup("ALL BUT CONFIGURED", &all_but_configured);
        let mut error_so_far = ConfiguratorError::new(vec![]);
        let (real_user_opt, data_directory_opt, chain) =
            match Self::calculate_fundamentals(self.dirs_wrapper.as_ref(), &all_but_configured) {
                Ok(triple) => triple,
                Err(error) => {
                    error_so_far.extend(error);
                    (None, None, DEFAULT_CHAIN)
                }
            };
        let real_user = real_user_opt.unwrap_or_else(|| {
            crate::bootstrapper::RealUser::new(None, None, None)
                .populate(self.dirs_wrapper.as_ref())
        });

        let (data_directory, data_dir_status) = self.get_data_directory_and_status(
            existing_setup.get("data-directory"),
            incoming_setup.get("data-directory"),
            &all_but_configured,
            chain,
            real_user,
            data_directory_opt,
        );
        let data_directory_setup =
            Self::construct_cluster_with_only_data_directory(&data_directory, data_dir_status);
        let (configured_setup, error_opt) =
            self.calculate_configured_setup(&all_but_configured, &data_directory);
        if let Some(error) = error_opt {
            error_so_far.extend(error);
        }
        error_so_far.param_errors.iter().for_each(|param_error| {
            let _ = incoming_setup.remove(&param_error.parameter);
        });
        let combined_setup = Self::combine_clusters(vec![
            &all_but_configured,
            &configured_setup,
            &data_directory_setup,
        ]);
        eprintln_setup("DATA DIRECTORY SETUP", &data_directory_setup);
        eprintln_setup("CONFIGURED", &configured_setup);
        eprintln_setup("COMBINED", &combined_setup);
        let final_setup = value_retrievers(self.dirs_wrapper.as_ref())
            .into_iter()
            .map(|retriever| {
                let make_blank_or_required = || {
                    let status = if retriever.is_required(&combined_setup) {
                        Required
                    } else {
                        Blank
                    };
                    (
                        retriever.value_name().to_string(),
                        UiSetupResponseValue::new(retriever.value_name(), "", status),
                    )
                };
                match combined_setup.get(retriever.value_name()) {
                    Some(uisrv) if [Blank, Required].contains(&uisrv.status) => {
                        make_blank_or_required()
                    }
                    Some(uisrv) => (retriever.value_name().to_string(), uisrv.clone()),
                    None => make_blank_or_required(),
                }
            })
            .collect::<SetupCluster>();
        eprintln_setup("FINAL", &final_setup);
        if error_so_far.param_errors.is_empty() {
            Ok(final_setup)
        } else {
            let setup = Self::combine_clusters(vec![
                &final_setup,
                &blanked_out_former_values,
                &prevention_to_err_induced_setup_impairments,
            ]);
            Err((setup, error_so_far))
        }
    }
}

#[allow(dead_code)]
fn eprintln_setup(label: &str, cluster: &SetupCluster) {
    if !CONSOLE_DIAGNOSTICS {
        return;
    }
    let message = cluster
        .iter()
        .map(|(_, v)| (v.name.to_string(), v.value.to_string(), v.status))
        .sorted_by_key(|(n, _, _)| n.clone())
        .map(|(n, v, s)| format!("{:26}{:65}{:?}", n, v, s))
        .join("\n");
    eprintln!("{}:\n{}\n", label, message);
}

impl SetupReporterReal {
    pub fn new(dirs_wrapper: Box<dyn DirsWrapper>) -> Self {
        Self {
            dirs_wrapper,
            logger: Logger::new("SetupReporter"),
        }
    }

    pub fn get_default_params() -> SetupCluster {
        let schema = daemon_shared_app();
        schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name;
                match opt.v.default_val {
                    Some(os_str) => {
                        let value = os_str.to_str().expect("expected valid UTF-8");
                        Some((
                            name.to_string(),
                            UiSetupResponseValue::new(name, value, Default),
                        ))
                    }
                    None => None,
                }
            })
            .collect()
    }

    fn real_user_from_str(s: &str) -> Option<crate::bootstrapper::RealUser> {
        match crate::bootstrapper::RealUser::from_str(s) {
            Ok(ru) => Some(ru),
            Err(_) => None,
        }
    }

    fn prevent_err_induced_setup_impairments(
        blanked_out_former_setup: &SetupCluster,
        existing_setup: &SetupCluster,
    ) -> SetupCluster {
        // this function arose as an unconvincing patch for a corner case where a blanked-out parameter registers
        // while it heads off to an (unrelated) error which will make another parameter get out of sync with
        // the restored value for the blanked-out parameter; this special SetupCluster should remember the initial
        // state and help to restore both params the way they used to be
        ARG_PAIRS_SENSITIVE_TO_SETUP_ERRS
            .iter()
            .fold(HashMap::new(), |mut acc, pair| {
                if blanked_out_former_setup.contains_key(&pair.blanked_arg.to_string()) {
                    if let Some(existing_linked_value) =
                        existing_setup.get(&pair.linked_arg.to_string())
                    {
                        acc.insert(pair.linked_arg.to_string(), existing_linked_value.clone());
                    }
                };
                acc
            })
    }

    fn get_data_directory_and_status(
        &self,
        existing_setup_dir: Option<&UiSetupResponseValue>,
        incoming_setup_dir: Option<&UiSetupResponseValue>,
        all_but_configured: &SetupCluster,
        chain: masq_lib::blockchains::chains::Chain,
        real_user: crate::bootstrapper::RealUser,
        data_directory_opt: Option<PathBuf>,
    ) -> (PathBuf, UiSetupResponseValueStatus) {
        let (data_directory, data_dir_status) = match all_but_configured.get("data-directory") {
            Some(uisrv) if uisrv.status == Set => {
                Self::determine_setup_value_of_set_data_directory(
                    uisrv,
                    match existing_setup_dir {
                        Some(..) => existing_setup_dir,
                        None => None,
                    },
                    match incoming_setup_dir {
                        Some(..) => incoming_setup_dir,
                        None => None,
                    },
                    chain,
                )
            }
            _ => match data_directory_opt {
                //this can mean only that environment variables had it
                Some(data_dir) => (data_dir, UiSetupResponseValueStatus::Configured),
                None => {
                    let data_dir =
                        data_directory_from_context(self.dirs_wrapper.as_ref(), &real_user, chain);
                    (data_dir, Default)
                }
            },
        };
        (data_directory, data_dir_status)
    }

    fn determine_setup_value_of_set_data_directory(
        semi_clusters_val: &UiSetupResponseValue,
        existing_setup_dir: Option<&UiSetupResponseValue>,
        incoming_setup_dir: Option<&UiSetupResponseValue>,
        chain: BlockChain,
    ) -> (PathBuf, UiSetupResponseValueStatus) {
        match (existing_setup_dir, incoming_setup_dir) {
            (_, Some(_)) => (add_chain_specific_directory(chain, Path::new(&semi_clusters_val.value)), semi_clusters_val.status),
            (Some(recent_value),None) =>(Self::reconstitute_data_dir_by_chain(&recent_value.value, chain), recent_value.status),
            (None, None) => panic!("broken code: data-directory value is neither in existing_setup or incoming_setup and yet this value \"{}\" was found in the merged cluster", semi_clusters_val.value)
        }
    }

    fn reconstitute_data_dir_by_chain(
        previously_processed_data_dir: &str,
        current_chain: BlockChain,
    ) -> PathBuf {
        let mut path = PathBuf::from(&previously_processed_data_dir);
        path.pop();
        add_chain_specific_directory(current_chain, &path)
    }

    fn construct_cluster_with_only_data_directory(
        data_directory: &Path,
        data_dir_status: UiSetupResponseValueStatus,
    ) -> SetupCluster {
        let mut setup = HashMap::new();
        setup.insert(
            "data-directory".to_string(),
            UiSetupResponseValue::new(
                "data-directory",
                data_directory.to_str().expect("data-directory expected"),
                data_dir_status,
            ),
        );
        setup
    }

    fn calculate_fundamentals(
        dirs_wrapper: &dyn DirsWrapper,
        combined_setup: &SetupCluster,
    ) -> Result<
        (
            Option<crate::bootstrapper::RealUser>,
            Option<PathBuf>,
            BlockChain,
        ),
        ConfiguratorError,
    > {
        let multi_config = Self::make_multi_config(dirs_wrapper, None, true, false)?;
        let real_user_opt = match (
            value_m!(multi_config, "real-user", String),
            combined_setup.get("real-user"),
        ) {
            (Some(real_user_str), None) => Self::real_user_from_str(&real_user_str),
            (Some(_), Some(uisrv)) if uisrv.status == Set => Self::real_user_from_str(&uisrv.value),
            (Some(real_user_str), Some(_)) => Self::real_user_from_str(&real_user_str),
            (None, Some(uisrv)) => Self::real_user_from_str(&uisrv.value),
            (None, None) => {
                Some(crate::bootstrapper::RealUser::new(None, None, None).populate(dirs_wrapper))
            }
        };
        let chain_name = match (
            value_m!(multi_config, "chain", String),
            combined_setup.get("chain"),
        ) {
            (Some(chain), None) => chain,
            (Some(_), Some(uisrv)) if uisrv.status == Set => uisrv.value.clone(),
            (Some(chain_str), Some(_)) => chain_str,
            (None, Some(uisrv)) => uisrv.value.clone(),
            (None, None) => DEFAULT_CHAIN.rec().literal_identifier.to_string(),
        };
        let data_directory_opt = match (
            value_m!(multi_config, "data-directory", String),
            combined_setup.get("data-directory"),
        ) {
            (Some(ddir_str), None) => Some(PathBuf::from(&ddir_str)),
            (Some(_), Some(uisrv)) if uisrv.status == Set => Some(PathBuf::from(&uisrv.value)),
            (Some(ddir_str), Some(_)) => Some(PathBuf::from(&ddir_str)),
            _ => None,
        };
        Ok((
            real_user_opt,
            data_directory_opt,
            BlockChain::from(chain_name.as_str()),
        ))
    }

    fn calculate_configured_setup(
        &self,
        combined_setup: &SetupCluster,
        data_directory: &Path,
    ) -> (SetupCluster, Option<ConfiguratorError>) {
        let mut error_so_far = ConfiguratorError::new(vec![]);
        let db_password_opt = combined_setup.get("db-password").map(|v| v.value.clone());
        let command_line = Self::make_command_line(combined_setup);
        let multi_config = match Self::make_multi_config(
            self.dirs_wrapper.as_ref(),
            Some(command_line),
            true,
            true,
        ) {
            Ok(mc) => mc,
            Err(ce) => return (HashMap::new(), Some(ce)),
        };
        let ((bootstrapper_config, persistent_config), error_opt) =
            self.run_configuration(&multi_config, data_directory);
        if let Some(error) = error_opt {
            error_so_far.extend(error);
        }
        let mut setup = value_retrievers(self.dirs_wrapper.as_ref())
            .into_iter()
            .map(|r| {
                let computed_default = r.computed_default_value(
                    &bootstrapper_config,
                    persistent_config.as_ref(),
                    &db_password_opt,
                );
                let configured = match value_m!(multi_config, r.value_name(), String) {
                    Some(value) => UiSetupResponseValue::new(r.value_name(), &value, Configured),
                    None => UiSetupResponseValue::new(r.value_name(), "", Blank),
                };
                let value = Self::choose_uisrv(&computed_default, &configured).clone();
                (r.value_name().to_string(), value)
            })
            .collect::<SetupCluster>();
        match setup.get_mut("config-file") {
            // special case because of early processing
            Some(uisrv) if &uisrv.value == "config.toml" => uisrv.status = Default,
            _ => (),
        };
        if error_so_far.param_errors.is_empty() {
            (setup, None)
        } else {
            (setup, Some(error_so_far))
        }
    }

    fn combine_clusters(clusters: Vec<&SetupCluster>) -> SetupCluster {
        let mut result: SetupCluster = HashMap::new();
        clusters.into_iter().for_each(|cluster| {
            let mut step: SetupCluster = HashMap::new();
            cluster.iter().for_each(|(k, incoming)| {
                match result.get(k) {
                    Some(existing) => {
                        step.insert(k.clone(), Self::choose_uisrv(existing, incoming).clone())
                    }
                    None => step.insert(k.clone(), incoming.clone()),
                };
            });
            result.extend(step);
        });
        result
    }

    fn choose_uisrv<'a>(
        existing: &'a UiSetupResponseValue,
        incoming: &'a UiSetupResponseValue,
    ) -> &'a UiSetupResponseValue {
        if incoming.status.priority() >= existing.status.priority() {
            incoming
        } else {
            existing
        }
    }

    fn make_command_line(setup: &SetupCluster) -> Vec<String> {
        let accepted_statuses = vec![Set, Configured];
        let mut command_line = setup
            .iter()
            .filter(|(_, v)| accepted_statuses.contains(&v.status))
            .flat_map(|(_, v)| vec![format!("--{}", v.name), v.value.clone()])
            .collect::<Vec<String>>();
        command_line.insert(0, "program_name".to_string());
        command_line
    }

    fn make_multi_config<'a>(
        dirs_wrapper: &dyn DirsWrapper,
        command_line_opt: Option<Vec<String>>,
        environment: bool,
        config_file: bool,
    ) -> Result<MultiConfig<'a>, ConfiguratorError> {
        let app = daemon_shared_app();
        let mut vcls: Vec<Box<dyn VirtualCommandLine>> = vec![];
        if let Some(command_line) = command_line_opt.clone() {
            vcls.push(Box::new(CommandLineVcl::new(command_line)));
        }
        if config_file {
            let command_line = match command_line_opt {
                Some(command_line) => command_line,
                None => vec![],
            };
            let user_specific_data =
                determine_user_specific_data(dirs_wrapper, &app, &command_line)?;
            let config_file_vcl = match ConfigFileVcl::new(
                &user_specific_data.config_file.item,
                user_specific_data.config_file.user_specified,
            ) {
                Ok(cfv) => cfv,
                Err(e) => return Err(ConfiguratorError::required("config-file", &e.to_string())),
            };
            vcls.push(Box::new(config_file_vcl));
        }
        if environment {
            vcls.push(Box::new(EnvironmentVcl::new(&app)));
        }
        make_new_multi_config(&app, vcls)
    }

    #[allow(clippy::type_complexity)]
    fn run_configuration(
        &self,
        multi_config: &MultiConfig,
        data_directory: &Path,
    ) -> (
        (BootstrapperConfig, Box<dyn PersistentConfiguration>),
        Option<ConfiguratorError>,
    ) {
        let mut error_so_far = ConfiguratorError::new(vec![]);
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.data_directory = data_directory.to_path_buf();
        match privileged_parse_args(
            self.dirs_wrapper.as_ref(),
            multi_config,
            &mut bootstrapper_config,
        ) {
            Ok(_) => (),
            Err(ce) => {
                error_so_far.extend(ce);
            }
        };
        let initializer = DbInitializerReal::default();
        match initializer.initialize(
            data_directory,
            DbInitializationConfig::migration_suppressed_with_error(),
        ) {
            Ok(conn) => {
                let parse_args_configuration = UnprivilegedParseArgsConfigurationDaoReal {};
                let mut persistent_config = PersistentConfigurationReal::from(conn);
                match parse_args_configuration.unprivileged_parse_args(
                    multi_config,
                    &mut bootstrapper_config,
                    &mut persistent_config,
                    &self.logger,
                ) {
                    Ok(_) => ((bootstrapper_config, Box::new(persistent_config)), None),
                    Err(ce) => {
                        error_so_far.extend(ce);
                        (
                            (bootstrapper_config, Box::new(persistent_config)),
                            Some(error_so_far),
                        )
                    }
                }
            }
            Err(InitializationError::Nonexistent | InitializationError::SuppressedMigration) => {
                // When the Daemon runs for the first time, the database will not yet have been
                // created. If the database is old, it should not be used by the Daemon (see more
                // details at ConfigDaoNull).

                let parse_args_configuration = UnprivilegedParseArgsConfigurationDaoNull {};
                let mut persistent_config =
                    PersistentConfigurationReal::new(Box::new(ConfigDaoNull::default()));
                match parse_args_configuration.unprivileged_parse_args(
                    multi_config,
                    &mut bootstrapper_config,
                    &mut persistent_config,
                    &self.logger,
                ) {
                    Ok(_) => ((bootstrapper_config, Box::new(persistent_config)), None),
                    Err(ce) => {
                        error_so_far.extend(ce);

                        (
                            (bootstrapper_config, Box::new(persistent_config)),
                            Some(error_so_far),
                        )
                    }
                }
            }
            Err(e) => panic!("Couldn't initialize database: {:?}", e),
        }
    }
}

struct ErrorSensitiveArgPair<'arg_names> {
    blanked_arg: &'arg_names str,
    linked_arg: &'arg_names str,
}

trait ValueRetriever {
    fn value_name(&self) -> &'static str;

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        None
    }

    fn computed_default_value(
        &self,
        bootstrapper_config: &BootstrapperConfig,
        persistent_config: &dyn PersistentConfiguration,
        db_password_opt: &Option<String>,
    ) -> UiSetupResponseValue {
        match self.computed_default(bootstrapper_config, persistent_config, db_password_opt) {
            Some((value, status)) => UiSetupResponseValue::new(self.value_name(), &value, status),
            None => UiSetupResponseValue::new(self.value_name(), "", Blank),
        }
    }

    fn set_value(&self, multi_config: &MultiConfig) -> Option<String> {
        value_m!(multi_config, self.value_name(), String)
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        false
    }
}

fn is_required_for_blockchain(params: &SetupCluster) -> bool {
    !matches! (params.get("neighborhood-mode"), Some(nhm) if &nhm.value == "zero-hop")
}

struct BlockchainServiceUrl {}
impl ValueRetriever for BlockchainServiceUrl {
    fn value_name(&self) -> &'static str {
        "blockchain-service-url"
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        is_required_for_blockchain(params)
    }
}

struct Chain {}
impl ValueRetriever for Chain {
    fn value_name(&self) -> &'static str {
        "chain"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        Some((DEFAULT_CHAIN.rec().literal_identifier.to_string(), Default))
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct ClandestinePort {}
impl ValueRetriever for ClandestinePort {
    fn value_name(&self) -> &'static str {
        "clandestine-port"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        match persistent_config.clandestine_port() {
            Ok(clandestine_port) => Some((clandestine_port.to_string(), Configured)),
            Err(_) => None,
        }
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct ConfigFile {}
impl ValueRetriever for ConfigFile {
    fn value_name(&self) -> &'static str {
        "config-file"
    }
}

struct ConsumingPrivateKey {}
impl ValueRetriever for ConsumingPrivateKey {
    fn value_name(&self) -> &'static str {
        "consuming-private-key"
    }
}

struct CrashPoint {}
impl ValueRetriever for CrashPoint {
    fn value_name(&self) -> &'static str {
        "crash-point"
    }
}

struct DataDirectory {
    dirs_wrapper: Box<dyn DirsWrapper>,
}
impl ValueRetriever for DataDirectory {
    fn value_name(&self) -> &'static str {
        "data-directory"
    }

    fn computed_default(
        &self,
        bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        let real_user = &bootstrapper_config.real_user;
        let chain = bootstrapper_config.blockchain_bridge_config.chain;
        Some((
            data_directory_from_context(self.dirs_wrapper.as_ref(), real_user, chain)
                .to_string_lossy()
                .to_string(),
            Default,
        ))
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}
impl std::default::Default for DataDirectory {
    fn default() -> Self {
        Self::new(&DirsWrapperReal::default())
    }
}
impl DataDirectory {
    pub fn new(dirs_wrapper: &dyn DirsWrapper) -> Self {
        Self {
            dirs_wrapper: dirs_wrapper.dup(),
        }
    }
}

struct DbPassword {}
impl ValueRetriever for DbPassword {
    fn value_name(&self) -> &'static str {
        "db-password"
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        is_required_for_blockchain(params)
    }
}

struct DnsServers {
    factory: Box<dyn DnsInspectorFactory>,
    logger: Logger,
}
impl DnsServers {
    pub fn new() -> Self {
        Self {
            factory: Box::new(DnsInspectorFactoryReal::new()),
            logger: Logger::new("DnsServers"),
        }
    }
}
impl ValueRetriever for DnsServers {
    fn value_name(&self) -> &'static str {
        "dns-servers"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        let inspector = self.factory.make()?;
        match inspector.inspect() {
            Ok(ip_addrs) => {
                if ip_addrs.is_empty() {
                    return None;
                }
                if ip_addrs.iter().any(|ip_addr| ip_addr.is_loopback()) {
                    return None;
                }
                let dns_servers = ip_addrs.into_iter().map(to_string).join(",");
                Some((dns_servers, Default))
            }
            Err(e) => {
                warning!(self.logger, "Error inspecting DNS settings: {:?}", e);
                None
            }
        }
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        !matches!(_params.get("neighborhood-mode"), Some(nhm) if &nhm.value == "consume-only")
    }
}

struct EarningWallet {}
impl ValueRetriever for EarningWallet {
    fn value_name(&self) -> &'static str {
        "earning-wallet"
    }
}

struct GasPrice {}
impl ValueRetriever for GasPrice {
    fn value_name(&self) -> &'static str {
        "gas-price"
    }

    fn computed_default(
        &self,
        bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        Some((
            bootstrapper_config
                .blockchain_bridge_config
                .gas_price
                .to_string(),
            Default,
        ))
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        is_required_for_blockchain(params)
    }
}

struct Ip {}
impl ValueRetriever for Ip {
    fn value_name(&self) -> &'static str {
        "ip"
    }

    fn computed_default(
        &self,
        bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        let neighborhood_mode = &bootstrapper_config.neighborhood_config.mode;
        match neighborhood_mode {
            NeighborhoodModeEnum::Standard(node_addr, _, _)
                if node_addr.ip_addr() == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) =>
            {
                Some(("".to_string(), UiSetupResponseValueStatus::Blank))
            }
            NeighborhoodModeEnum::Standard(node_addr, _, _) => Some((
                node_addr.ip_addr().to_string(),
                UiSetupResponseValueStatus::Set,
            )),
            _ => Some(("".to_string(), UiSetupResponseValueStatus::Blank)),
        }
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        false
    }
}

struct LogLevel {}
impl ValueRetriever for LogLevel {
    fn value_name(&self) -> &'static str {
        "log-level"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        Some(("warn".to_string(), Default))
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct MappingProtocol {}
impl ValueRetriever for MappingProtocol {
    fn value_name(&self) -> &'static str {
        "mapping-protocol"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        let persistent_config_value_opt = match persistent_config.mapping_protocol() {
            Ok(protocol_opt) => protocol_opt,
            Err(_) => None,
        };
        persistent_config_value_opt
            .map(|protocol| (protocol.to_string().to_lowercase(), Configured))
    }
}

struct MinHops {
    logger: Logger,
}

impl MinHops {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("MinHops"),
        }
    }
}

impl ValueRetriever for MinHops {
    fn value_name(&self) -> &'static str {
        "min-hops"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        match persistent_config.min_hops() {
            Ok(min_hops) => Some(if min_hops == DEFAULT_MIN_HOPS {
                (DEFAULT_MIN_HOPS.to_string(), Default)
            } else {
                (min_hops.to_string(), Configured)
            }),
            Err(e) => {
                error!(
                    self.logger,
                    "No value for min hops found in database; database is corrupt: {:?}", e
                );
                None
            }
        }
    }
}

struct NeighborhoodMode {}
impl ValueRetriever for NeighborhoodMode {
    fn value_name(&self) -> &'static str {
        "neighborhood-mode"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        Some(("standard".to_string(), Default))
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

fn node_descriptors_to_neighbors(node_descriptors: Vec<NodeDescriptor>) -> String {
    node_descriptors
        .into_iter()
        .map(|nd| nd.to_string(main_cryptde()))
        .collect_vec()
        .join(",")
}

struct Neighbors {}
impl ValueRetriever for Neighbors {
    fn value_name(&self) -> &'static str {
        "neighbors"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        persistent_config: &dyn PersistentConfiguration,
        db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        match db_password_opt {
            Some(pw) => match persistent_config.past_neighbors(pw) {
                Ok(Some(pns)) => Some((node_descriptors_to_neighbors(pns), Configured)),
                _ => None,
            },
            None => None,
        }
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        match params.get("neighborhood-mode") {
            Some(nhm) if &nhm.value == "standard" => false,
            Some(nhm) if &nhm.value == "zero-hop" => false,
            _ => true,
        }
    }
}

struct PaymentThresholds {}
impl ValueRetriever for PaymentThresholds {
    fn value_name(&self) -> &'static str {
        "payment-thresholds"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        pc: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        let pc_value = pc.payment_thresholds().expectv("payment-thresholds");
        payment_thresholds_rate_pack_and_scan_intervals(
            pc_value,
            PaymentThresholdsFromAccountant::default(),
        )
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct RatePack {}
impl ValueRetriever for RatePack {
    fn value_name(&self) -> &'static str {
        "rate-pack"
    }

    fn computed_default(
        &self,
        bootstrapper_config: &BootstrapperConfig,
        pc: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        match &bootstrapper_config.neighborhood_config.mode {
            NeighborhoodModeEnum::Standard(_, _, _) | NeighborhoodModeEnum::OriginateOnly(_, _) => {
            }
            _ => return None,
        }
        let pc_value = pc.rate_pack().expectv("rate-pack");
        payment_thresholds_rate_pack_and_scan_intervals(pc_value, DEFAULT_RATE_PACK)
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        match params.get("neighborhood-mode") {
            Some(nhm) if &nhm.value == "standard" => true,
            Some(nhm) if &nhm.value == "originate-only" => true,
            _ => false,
        }
    }
}

struct ScanIntervals {}
impl ValueRetriever for ScanIntervals {
    fn value_name(&self) -> &'static str {
        "scan-intervals"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        pc: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        let pc_value = pc.scan_intervals().expectv("scan-intervals");
        payment_thresholds_rate_pack_and_scan_intervals(pc_value, *DEFAULT_SCAN_INTERVALS)
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

fn payment_thresholds_rate_pack_and_scan_intervals<T>(
    persistent_config_value: T,
    default: T,
) -> Option<(String, UiSetupResponseValueStatus)>
where
    T: PartialEq + Display + Clone,
{
    if persistent_config_value == default {
        Some((default.to_string(), Default))
    } else {
        Some((persistent_config_value.to_string(), Configured))
    }
}

struct RealUser {
    #[allow(dead_code)]
    dirs_wrapper: Box<dyn DirsWrapper>,
}
impl ValueRetriever for RealUser {
    fn value_name(&self) -> &'static str {
        "real-user"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        #[cfg(target_os = "windows")]
        {
            None
        }
        #[cfg(not(target_os = "windows"))]
        {
            Some((
                crate::bootstrapper::RealUser::new(None, None, None)
                    .populate(self.dirs_wrapper.as_ref())
                    .to_string(),
                Default,
            ))
        }
    }
}
impl std::default::Default for RealUser {
    fn default() -> Self {
        Self::new(&DirsWrapperReal::default())
    }
}
impl RealUser {
    pub fn new(dirs_wrapper: &dyn DirsWrapper) -> Self {
        Self {
            dirs_wrapper: dirs_wrapper.dup(),
        }
    }
}

struct Scans {}
impl ValueRetriever for Scans {
    fn value_name(&self) -> &'static str {
        "scans"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config: &dyn PersistentConfiguration,
        _db_password_opt: &Option<String>,
    ) -> Option<(String, UiSetupResponseValueStatus)> {
        Some(("on".to_string(), Default))
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        false
    }
}

fn value_retrievers(dirs_wrapper: &dyn DirsWrapper) -> Vec<Box<dyn ValueRetriever>> {
    vec![
        Box::new(BlockchainServiceUrl {}),
        Box::new(Chain {}),
        Box::new(ClandestinePort {}),
        Box::new(ConfigFile {}),
        Box::new(ConsumingPrivateKey {}),
        Box::new(CrashPoint {}),
        Box::new(DataDirectory::new(dirs_wrapper)),
        Box::new(DbPassword {}),
        Box::new(DnsServers::new()),
        Box::new(EarningWallet {}),
        Box::new(GasPrice {}),
        Box::new(Ip {}),
        Box::new(LogLevel {}),
        Box::new(MappingProtocol {}),
        Box::new(MinHops::new()),
        Box::new(NeighborhoodMode {}),
        Box::new(Neighbors {}),
        Box::new(PaymentThresholds {}),
        Box::new(RatePack {}),
        Box::new(ScanIntervals {}),
        #[cfg(not(target_os = "windows"))]
        Box::new(RealUser::new(dirs_wrapper)),
        Box::new(Scans {}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrapper::RealUser;
    use crate::daemon::dns_inspector::dns_inspector::DnsInspector;
    use crate::daemon::dns_inspector::DnsInspectionError;
    use crate::daemon::setup_reporter;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::db_config::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::db_config::persistent_configuration::{
        PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::node_configurator::{DirsWrapper, DirsWrapperReal};
    use crate::node_test_utils::DirsWrapperMock;
    use crate::sub_lib::accountant::{
        PaymentThresholds as PaymentThresholdsFromAccountant, DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::neighborhood::Hops;
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::sub_lib::{accountant, neighborhood};
    use crate::test_utils::database_utils::bring_db_0_back_to_life_and_return_connection;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::unshared_test_utils::{
        make_persistent_config_real_with_config_dao_null,
        make_pre_populated_mocked_directory_wrapper, make_simplified_multi_config,
    };
    use crate::test_utils::{
        assert_string_contains,
        make_node_base_dir_and_return_its_absolute_and_relative_path_to_os_home_dir, rate_pack,
    };
    use core::option::Option;
    use masq_lib::blockchains::chains::Chain as Blockchain;
    use masq_lib::blockchains::chains::Chain::PolyAmoy;
    use masq_lib::constants::{DEFAULT_CHAIN, DEFAULT_GAS_PRICE};
    use masq_lib::messages::UiSetupResponseValueStatus::{Blank, Configured, Required, Set};
    use masq_lib::test_utils::environment_guard::{ClapGuard, EnvironmentGuard};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::{add_chain_specific_directory, AutomapProtocol};
    use std::cell::RefCell;
    use std::convert::TryFrom;
    #[cfg(not(target_os = "windows"))]
    use std::default::Default;
    use std::fs::{create_dir_all, File};
    use std::io::Write;
    use std::net::IpAddr;
    use std::ops::{Add, Sub};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CONSOLE_DIAGNOSTICS, false);
    }

    pub struct DnsInspectorMock {
        inspect_results: RefCell<Vec<Result<Vec<IpAddr>, DnsInspectionError>>>,
    }

    impl DnsInspector for DnsInspectorMock {
        fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError> {
            self.inspect_results.borrow_mut().remove(0)
        }
    }

    impl DnsInspectorMock {
        pub fn new() -> DnsInspectorMock {
            DnsInspectorMock {
                inspect_results: RefCell::new(vec![]),
            }
        }

        pub fn inspect_result(
            self,
            result: Result<Vec<IpAddr>, DnsInspectionError>,
        ) -> DnsInspectorMock {
            self.inspect_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Default)]
    pub struct DnsModifierFactoryMock {
        make_results: RefCell<Vec<Option<Box<dyn DnsInspector>>>>,
    }

    impl DnsInspectorFactory for DnsModifierFactoryMock {
        fn make(&self) -> Option<Box<dyn DnsInspector>> {
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl DnsModifierFactoryMock {
        pub fn new() -> DnsModifierFactoryMock {
            DnsModifierFactoryMock {
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_result(self, result: Option<Box<dyn DnsInspector>>) -> DnsModifierFactoryMock {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn everything_in_defaults_is_properly_constructed() {
        let result = SetupReporterReal::get_default_params();

        assert_eq!(result.is_empty(), true, "{:?}", result); // if we have any defaults, let's get back to false statement here and assert right value line below
        result.into_iter().for_each(|(name, value)| {
            assert_eq!(name, value.name);
            assert_eq!(value.status, Default);
        });
    }

    #[test]
    fn some_items_are_censored_from_defaults() {
        let result = SetupReporterReal::get_default_params();

        assert_eq!(result.get("ui-port"), None, "{:?}", result);
        #[cfg(target_os = "windows")]
        assert_eq!(result.get("real-user"), None, "{:?}", result);
    }

    #[test]
    fn get_modified_setup_database_populated_only_requireds_set() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_database_populated_only_requireds_set",
        );
        let data_dir = home_dir.join("data_dir");
        let chain_specific_data_dir = data_dir.join(DEFAULT_CHAIN.rec().literal_identifier);
        std::fs::create_dir_all(&chain_specific_data_dir).unwrap();
        let db_initializer = DbInitializerReal::default();
        let conn = db_initializer
            .initialize(
                &chain_specific_data_dir,
                DbInitializationConfig::test_default(),
            )
            .unwrap();
        let mut config = PersistentConfigurationReal::from(conn);
        config.change_password(None, "password").unwrap();
        config.set_clandestine_port(1234).unwrap();
        config
            .set_wallet_info(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0x0000000000000000000000000000000000000000",
                "password",
            )
            .unwrap();
        config.set_gas_price(1234567890).unwrap();
        let neighbor1 = NodeDescriptor {
            encryption_public_key: PublicKey::new(b"ABCD"),
            blockchain: Blockchain::EthMainnet,
            node_addr_opt: Some(NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &[1234],
            )),
        };
        let neighbor2 = NodeDescriptor {
            encryption_public_key: PublicKey::new(b"EFGH"),
            blockchain: Blockchain::EthMainnet,
            node_addr_opt: Some(NodeAddr::new(
                &IpAddr::from_str("5.6.7.8").unwrap(),
                &[5678],
            )),
        };
        config
            .set_past_neighbors(Some(vec![neighbor1, neighbor2]), "password")
            .unwrap();
        let incoming_setup = vec![
            ("blockchain-service-url", "https://well-known-provider.com"),
            ("data-directory", data_dir.to_str().unwrap()),
            ("db-password", "password"),
            ("ip", "4.3.2.1"),
        ]
        .into_iter()
        .map(|(name, value)| UiSetupRequestValue::new(name, value))
        .collect_vec();
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(HashMap::new(), incoming_setup)
            .unwrap();

        let (dns_servers_str, dns_servers_status) = match DnsServers::new().computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        ) {
            Some((dss, _)) => (dss, Default),
            None => ("".to_string(), Required),
        };
        let expected_result = vec![
            (
                "blockchain-service-url",
                "https://well-known-provider.com",
                Set,
            ),
            ("chain", DEFAULT_CHAIN.rec().literal_identifier, Default),
            ("clandestine-port", "1234", Configured),
            ("config-file", "", Blank),
            ("consuming-private-key", "", Blank),
            ("crash-point", "", Blank),
            (
                "data-directory",
                data_dir
                    .join(DEFAULT_CHAIN.rec().literal_identifier)
                    .to_str()
                    .unwrap(),
                Set,
            ),
            ("db-password", "password", Set),
            ("dns-servers", &dns_servers_str, dns_servers_status),
            ("earning-wallet", "", Blank),
            ("gas-price", "1234567890", Default),
            ("ip", "4.3.2.1", Set),
            ("log-level", "warn", Default),
            ("mapping-protocol", "", Blank),
            ("min-hops", &DEFAULT_MIN_HOPS.to_string(), Default),
            ("neighborhood-mode", "standard", Default),
            (
                "neighbors",
                "masq://eth-mainnet:QUJDRA@1.2.3.4:1234,masq://eth-mainnet:RUZHSA@5.6.7.8:5678",
                Configured,
            ),
            (
                "payment-thresholds",
                &DEFAULT_PAYMENT_THRESHOLDS.to_string(),
                Default,
            ),
            ("rate-pack", &DEFAULT_RATE_PACK.to_string(), Default),
            #[cfg(not(target_os = "windows"))]
            (
                "real-user",
                &RealUser::new(None, None, None)
                    .populate(&DirsWrapperReal::default())
                    .to_string(),
                Default,
            ),
            (
                "scan-intervals",
                &DEFAULT_SCAN_INTERVALS.to_string(),
                Default,
            ),
            ("scans", "on", Default),
        ]
        .into_iter()
        .map(|(name, value, status)| {
            (
                name.to_string(),
                UiSetupResponseValue::new(name, value, status),
            )
        })
        .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_everything_preexistent() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_database_nonexistent_everything_preexistent",
        );
        let previously_processed_data_dir =
            home_dir.join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        let existing_setup = setup_cluster_from(vec![
            ("blockchain-service-url", "https://example1.com", Set),
            ("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier, Set),
            ("clandestine-port", "1234", Set),
            ("config-file", "config.toml", Default),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Set),
            ("crash-point", "Message", Set),
            ("data-directory", previously_processed_data_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("dns-servers", "8.8.8.8", Set),
            ("earning-wallet", "0x0123456789012345678901234567890123456789", Set),
            ("gas-price", "50", Set),
            ("ip", "4.3.2.1", Set),
            ("log-level", "error", Set),
            ("mapping-protocol", "pmp", Set),
            ("min-hops", "2", Set),
            ("neighborhood-mode", "originate-only", Set),
            ("neighbors", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Set),
            ("payment-thresholds","1234|50000|1000|1000|20000|20000",Set),
            ("rate-pack","1|3|3|8",Set),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Set),
            ("scan-intervals","150|150|150",Set),
            ("scans", "off", Set),
        ]);
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject.get_modified_setup(existing_setup, vec![]).unwrap();

        let expected_result = vec![
            ("blockchain-service-url", "https://example1.com", Set),
            ("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier, Set),
            ("clandestine-port", "1234", Set),
            ("config-file", "config.toml", Default),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Set),
            ("crash-point", "Message", Set),
            ("data-directory", previously_processed_data_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("dns-servers", "8.8.8.8", Set),
            ("earning-wallet", "0x0123456789012345678901234567890123456789", Set),
            ("gas-price", "50", Set),
            ("ip", "4.3.2.1", Set),
            ("log-level", "error", Set),
            ("mapping-protocol", "pmp", Set),
            ("min-hops", "2", Set),
            ("neighborhood-mode", "originate-only", Set),
            ("neighbors", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Set),
            ("payment-thresholds","1234|50000|1000|1000|20000|20000",Set),
            ("rate-pack","1|3|3|8",Set),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Set),
            ("scan-intervals","150|150|150",Set),
            ("scans", "off", Set),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_everything_set() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_database_nonexistent_everything_set",
        );
        let incoming_setup = vec![
            ("blockchain-service-url", "https://example2.com"),
            ("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier),
            ("clandestine-port", "1234"),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677"),
            ("crash-point", "Message"),
            ("data-directory", home_dir.to_str().unwrap()),
            ("db-password", "password"),
            ("dns-servers", "8.8.8.8"),
            ("earning-wallet", "0x0123456789012345678901234567890123456789"),
            ("gas-price", "50"),
            ("ip", "4.3.2.1"),
            ("log-level", "error"),
            ("mapping-protocol", "igdp"),
            ("min-hops", "2"),
            ("neighborhood-mode", "originate-only"),
            ("neighbors", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678"),
            ("payment-thresholds","1234|50000|1000|1000|15000|15000"),
            ("rate-pack","1|3|3|8"),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga"),
            ("scan-intervals","140|130|150"),
            ("scans", "off"),
        ].into_iter()
            .map (|(name, value)| UiSetupRequestValue::new(name, value))
            .collect_vec();
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(HashMap::new(), incoming_setup)
            .unwrap();

        let chain_specific_data_dir = add_chain_specific_directory(TEST_DEFAULT_CHAIN, &home_dir);
        let expected_result = vec![
            ("blockchain-service-url", "https://example2.com", Set),
            ("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier, Set),
            ("clandestine-port", "1234", Set),
            ("config-file", "", Blank),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Set),
            ("crash-point", "Message", Set),
            ("data-directory", chain_specific_data_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("dns-servers", "8.8.8.8", Set),
            ("earning-wallet", "0x0123456789012345678901234567890123456789", Set),
            ("gas-price", "50", Set),
            ("ip", "4.3.2.1", Set),
            ("log-level", "error", Set),
            ("mapping-protocol", "igdp", Set),
            ("min-hops", "2", Set),
            ("neighborhood-mode", "originate-only", Set),
            ("neighbors", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Set),
            ("payment-thresholds","1234|50000|1000|1000|15000|15000",Set),
            ("rate-pack","1|3|3|8",Set),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Set),
            ("scan-intervals","140|130|150",Set),
            ("scans", "off", Set),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_nothing_set_everything_in_environment() {
        let _guard = EnvironmentGuard::new();
        let _clap_guard = ClapGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_database_nonexistent_nothing_set_everything_in_environment",
        );
        vec![
            ("MASQ_BLOCKCHAIN_SERVICE_URL", "https://example3.com"),
            ("MASQ_CHAIN", TEST_DEFAULT_CHAIN.rec().literal_identifier),
            ("MASQ_CLANDESTINE_PORT", "1234"),
            ("MASQ_CONSUMING_PRIVATE_KEY", "0011223344556677001122334455667700112233445566770011223344556677"),
            ("MASQ_CRASH_POINT", "Error"),
            ("MASQ_DATA_DIRECTORY", home_dir.to_str().unwrap()),
            ("MASQ_DB_PASSWORD", "password"),
            ("MASQ_DNS_SERVERS", "8.8.8.8"),
            ("MASQ_EARNING_WALLET", "0x0123456789012345678901234567890123456789"),
            ("MASQ_GAS_PRICE", "50"),
            ("MASQ_IP", "4.3.2.1"),
            ("MASQ_LOG_LEVEL", "error"),
            ("MASQ_MAPPING_PROTOCOL", "pmp"),
            ("MASQ_MIN_HOPS", "2"),
            ("MASQ_NEIGHBORHOOD_MODE", "originate-only"),
            ("MASQ_NEIGHBORS", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678"),
            ("MASQ_PAYMENT_THRESHOLDS","12345|50000|1000|1234|19000|20000"),
            ("MASQ_RATE_PACK","1|3|3|8"),
            #[cfg(not(target_os = "windows"))]
            ("MASQ_REAL_USER", "9999:9999:booga"),
            ("MASQ_SCANS", "off"),
            ("MASQ_SCAN_INTERVALS","133|133|111")
        ].into_iter()
            .for_each (|(name, value)| std::env::set_var (name, value));
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let params = vec![];
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject.get_modified_setup(HashMap::new(), params).unwrap();

        let expected_result = vec![
            ("blockchain-service-url", "https://example3.com", Configured),
            ("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier, Configured),
            ("clandestine-port", "1234", Configured),
            ("config-file", "", Blank),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Configured),
            ("crash-point", "Error", Configured),
            ("data-directory", home_dir.to_str().unwrap(), Configured),
            ("db-password", "password", Configured),
            ("dns-servers", "8.8.8.8", Configured),
            ("earning-wallet", "0x0123456789012345678901234567890123456789", Configured),
            ("gas-price", "50", Configured),
            ("ip", "4.3.2.1", Configured),
            ("log-level", "error", Configured),
            ("mapping-protocol", "pmp", Configured),
            ("min-hops", "2", Configured),
            ("neighborhood-mode", "originate-only", Configured),
            ("neighbors", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Configured),
            ("payment-thresholds","12345|50000|1000|1234|19000|20000",Configured),
            ("rate-pack","1|3|3|8",Configured),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Configured),
            ("scan-intervals","133|133|111",Configured),
            ("scans", "off", Configured),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    // NOTE: This test achieves what it's designed for--to demonstrate that loading a different
    // config file changes the setup in the database properly--but the scenario it's built on is
    // misleading. You can't change a database from one chain to another, because in so doing all
    // its wallet addresses, balance amounts, and transaction numbers would be invalidated.
    fn switching_config_files_changes_setup() {
        let _ = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "switching_config_files_changes_setup",
        );
        let data_root = home_dir.join("data_root");
        let mainnet_dir = data_root
            .join("MASQ")
            .join(DEFAULT_CHAIN.rec().literal_identifier);
        {
            std::fs::create_dir_all(mainnet_dir.clone()).unwrap();
            let mut config_file = File::create(mainnet_dir.join("config.toml")).unwrap();
            config_file
                .write_all(b"blockchain-service-url = \"https://www.mainnet.com\"\n")
                .unwrap();
            config_file
                .write_all(b"clandestine-port = \"7788\"\n")
                .unwrap();
            config_file.write_all(b"consuming-private-key = \"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\"\n").unwrap();
            config_file.write_all(b"crash-point = \"Error\"\n").unwrap();
            config_file
                .write_all(b"db-password = \"mainnetPassword\"\n")
                .unwrap();
            config_file
                .write_all(b"dns-servers = \"5.6.7.8\"\n")
                .unwrap();
            config_file
                .write_all(b"earning-wallet = \"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n")
                .unwrap();
            config_file.write_all(b"gas-price = \"77\"\n").unwrap();
            config_file.write_all(b"log-level = \"trace\"\n").unwrap();
            config_file
                .write_all(b"mapping-protocol = \"pcp\"\n")
                .unwrap();
            config_file.write_all(b"min-hops = \"6\"\n").unwrap();
            config_file
                .write_all(b"neighborhood-mode = \"standard\"\n")
                .unwrap();
            config_file.write_all(b"scans = \"off\"\n").unwrap();
            config_file.write_all(b"rate-pack = \"2|2|2|2\"\n").unwrap();
            config_file
                .write_all(b"payment-thresholds = \"3333|55|33|646|999|999\"\n")
                .unwrap();
            config_file
                .write_all(b"scan-intervals = \"111|100|99\"\n")
                .unwrap()
        }
        let ropsten_dir = data_root
            .join("MASQ")
            .join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        {
            std::fs::create_dir_all(ropsten_dir.clone()).unwrap();
            let mut config_file = File::create(ropsten_dir.join("config.toml")).unwrap();
            config_file
                .write_all(b"blockchain-service-url = \"https://www.ropsten.com\"\n")
                .unwrap();
            config_file
                .write_all(b"clandestine-port = \"8877\"\n")
                .unwrap();
            // NOTE: You can't really change consuming-private-key without starting a new database
            config_file.write_all(b"consuming-private-key = \"FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100\"\n").unwrap();
            config_file.write_all(b"crash-point = \"None\"\n").unwrap();
            config_file
                .write_all(b"db-password = \"ropstenPassword\"\n")
                .unwrap();
            config_file
                .write_all(b"dns-servers = \"8.7.6.5\"\n")
                .unwrap();
            // NOTE: You can't really change consuming-private-key without starting a new database
            config_file
                .write_all(b"earning-wallet = \"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n")
                .unwrap();
            config_file.write_all(b"gas-price = \"88\"\n").unwrap();
            config_file.write_all(b"log-level = \"debug\"\n").unwrap();
            config_file
                .write_all(b"mapping-protocol = \"pmp\"\n")
                .unwrap();
            config_file.write_all(b"min-hops = \"2\"\n").unwrap();
            config_file
                .write_all(b"neighborhood-mode = \"zero-hop\"\n")
                .unwrap();
            config_file.write_all(b"scans = \"off\"\n").unwrap();
            config_file
                .write_all(b"rate-pack = \"55|50|60|61\"\n")
                .unwrap();
            config_file
                .write_all(b"payment-thresholds = \"4000|1000|3000|3333|10000|20000\"\n")
                .unwrap();
            config_file
                .write_all(b"scan-intervals = \"555|555|555\"\n")
                .unwrap()
        }
        let subject = SetupReporterReal::new(Box::new(
            DirsWrapperMock::new()
                .home_dir_result(Some(home_dir.clone()))
                .data_dir_result(Some(data_root.clone())),
        ));
        let params = vec![UiSetupRequestValue::new(
            "chain",
            DEFAULT_CHAIN.rec().literal_identifier,
        )];
        let existing_setup = subject.get_modified_setup(HashMap::new(), params).unwrap();
        let params = vec![UiSetupRequestValue::new(
            "chain",
            TEST_DEFAULT_CHAIN.rec().literal_identifier,
        )];

        let result = subject.get_modified_setup(existing_setup, params).unwrap();

        let expected_result = vec![
            (
                "blockchain-service-url",
                "https://www.ropsten.com",
                Configured,
            ),
            ("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier, Set),
            ("clandestine-port", "8877", Configured),
            ("config-file", "", Blank),
            (
                "consuming-private-key",
                "FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100",
                Configured,
            ),
            ("crash-point", "None", Configured),
            (
                "data-directory",
                &ropsten_dir.to_string_lossy().to_string(),
                Default,
            ),
            ("db-password", "ropstenPassword", Configured),
            ("dns-servers", "8.7.6.5", Configured),
            (
                "earning-wallet",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                Configured,
            ),
            ("gas-price", "88", Configured),
            ("ip", "", Blank),
            ("log-level", "debug", Configured),
            ("mapping-protocol", "pmp", Configured),
            ("min-hops", "2", Configured),
            ("neighborhood-mode", "zero-hop", Configured),
            ("neighbors", "", Blank),
            (
                "payment-thresholds",
                "4000|1000|3000|3333|10000|20000",
                Configured,
            ),
            ("rate-pack", "55|50|60|61", Configured),
            #[cfg(not(target_os = "windows"))]
            (
                "real-user",
                &crate::bootstrapper::RealUser::new(None, None, None)
                    .populate(subject.dirs_wrapper.as_ref())
                    .to_string(),
                Default,
            ),
            ("scan-intervals", "555|555|555", Configured),
            ("scans", "off", Configured),
        ]
        .into_iter()
        .map(|(name, value, status)| {
            (
                name.to_string(),
                UiSetupResponseValue::new(name, value, status),
            )
        })
        .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_all_but_requireds_cleared() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_database_nonexistent_all_but_requireds_cleared",
        );
        vec![
            ("MASQ_CHAIN", TEST_DEFAULT_CHAIN.rec().literal_identifier),
            ("MASQ_CLANDESTINE_PORT", "1234"),
            ("MASQ_CONSUMING_PRIVATE_KEY", "0011223344556677001122334455667700112233445566770011223344556677"),
            ("MASQ_CRASH_POINT", "Panic"),
            ("MASQ_DATA_DIRECTORY", home_dir.to_str().unwrap()),
            ("MASQ_DNS_SERVERS", "8.8.8.8"),
            ("MASQ_EARNING_WALLET", "0x0123456789012345678901234567890123456789"),
            ("MASQ_GAS_PRICE", "50"),
            ("MASQ_LOG_LEVEL", "error"),
            ("MASQ_MAPPING_PROTOCOL", "pcp"),
            ("MASQ_MIN_HOPS", "2"),
            ("MASQ_NEIGHBORHOOD_MODE", "originate-only"),
            ("MASQ_NEIGHBORS", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678"),
            ("MASQ_PAYMENT_THRESHOLDS","1234|50000|1000|1000|20000|20000"),
            ("MASQ_RATE_PACK","1|3|3|8"),
            #[cfg(not(target_os = "windows"))]
            ("MASQ_REAL_USER", "9999:9999:booga"),
            ("MASQ_SCANS", "off"),
            ("MASQ_SCAN_INTERVALS","150|150|155"),
        ].into_iter()
            .for_each (|(name, value)| std::env::set_var (name, value));
        let params = vec![
            "blockchain-service-url",
            "clandestine-port",
            "config-file",
            "consuming-private-key",
            "crash-point",
            "data-directory",
            "db-password",
            "dns-servers",
            "earning-wallet",
            "gas-price",
            "ip",
            "log-level",
            "mapping-protocol",
            "min-hops",
            "neighborhood-mode",
            "neighbors",
            "payment-thresholds",
            "rate-pack",
            #[cfg(not(target_os = "windows"))]
            "real-user",
            "scan-intervals",
            "scans",
        ]
        .into_iter()
        .map(|name| UiSetupRequestValue::clear(name))
        .collect_vec();
        let existing_setup =
            setup_cluster_from(vec![
            ("blockchain-service-url", "https://booga.com", Set),
            ("clandestine-port", "4321", Set),
            (
                "consuming-private-key",
                "7766554433221100776655443322110077665544332211007766554433221100",
                Set,
            ),
            ("crash-point", "Message", Set),
            ("data-directory", "booga", Set),
            ("db-password", "drowssap", Set),
            ("dns-servers", "4.4.4.4", Set),
            (
                "earning-wallet",
                "0x9876543210987654321098765432109876543210",
                Set,
            ),
            ("gas-price", "5", Set),
            ("ip", "1.2.3.4", Set),
            ("log-level", "error", Set),
            ("mapping-protocol", "pcp", Set),
            ("min-hops", "4", Set),
            ("neighborhood-mode", "consume-only", Set),
            (
                "neighbors",
                "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@9.10.11.12:9101",
                Set,
            ),
            ("payment-thresholds", "4321|66666|777|987|123456|124444", Set),
            ("rate-pack", "10|30|13|28", Set),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "6666:6666:agoob", Set),
            ("scan-intervals", "111|111|111", Set),
            ("scans", "off", Set),
            ]);
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject.get_modified_setup(existing_setup, params).unwrap();

        let expected_result = vec![
            ("blockchain-service-url", "", Required),
            ("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier, Configured),
            ("clandestine-port", "1234", Configured),
            ("config-file", "", Blank),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Configured),
            ("crash-point", "Panic", Configured),
            ("data-directory", home_dir.to_str().unwrap(), Configured),
            ("db-password", "",Required),
            ("dns-servers", "8.8.8.8", Configured),
            (
                "earning-wallet",
                "0x0123456789012345678901234567890123456789",
                Configured,
            ),
            ("gas-price", "50", Configured),
            ("ip","", Blank),
            ("log-level", "error", Configured),
            ("mapping-protocol", "pcp", Configured),
            ("min-hops", "2", Configured),
            ("neighborhood-mode", "originate-only", Configured),
            ("neighbors", "masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,masq://eth-ropsten:MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Configured),
            ("payment-thresholds","1234|50000|1000|1000|20000|20000",Configured),
            ("rate-pack","1|3|3|8",Configured),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Configured),
            ("scan-intervals","150|150|155",Configured),
            ("scans", "off", Configured),
        ]
        .into_iter()
        .map(|(name, value, status)| {
            (
                name.to_string(),
                UiSetupResponseValue::new(name, value, status),
            )
        })
        .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_default_data_directory_depends_on_new_chain_on_success() {
        let _guard = EnvironmentGuard::new();
        let base_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_default_data_directory_depends_on_new_chain_on_success",
        );
        let data_dir = base_dir.join("data_dir");
        let existing_setup = setup_cluster_from(vec![
            ("neighborhood-mode", "zero-hop", Set),
            ("chain", DEFAULT_CHAIN.rec().literal_identifier, Default),
            (
                "data-directory",
                &data_dir.to_string_lossy().to_string(),
                Default,
            ),
        ]);
        let incoming_setup = vec![("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier)]
            .into_iter()
            .map(|(name, value)| UiSetupRequestValue::new(name, value))
            .collect_vec();

        let expected_data_directory = data_dir
            .join("MASQ")
            .join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        let dirs_wrapper = Box::new(
            DirsWrapperMock::new()
                .data_dir_result(Some(data_dir))
                .home_dir_result(Some(base_dir)),
        );
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .unwrap();

        let actual_data_directory = PathBuf::from(&result.get("data-directory").unwrap().value);
        assert_eq!(actual_data_directory, expected_data_directory);
    }

    #[test]
    fn get_modified_setup_tilde_in_config_file_path() {
        let _guard = EnvironmentGuard::new();
        let (node_base_dir, node_base_dir_relative_to_os_home_dir) =
            make_node_base_dir_and_return_its_absolute_and_relative_path_to_os_home_dir(
                "setup_reporter",
                "get_modified_setup_tilde_in_config_file_path",
            );
        let existing_data_dir = node_base_dir.join("obsolete_data_dir");
        let new_dir_levels = PathBuf::new().join("whatever_dir").join("new_data_dir");
        let new_data_dir = node_base_dir.join(new_dir_levels.as_path());
        create_dir_all(new_data_dir.as_path()).unwrap();
        let mut config_file = File::create(new_data_dir.join("config.toml")).unwrap();
        config_file
            .write_all(b"blockchain-service-url = \"https://www.mainnet.com\"\n")
            .unwrap();
        let existing_setup = setup_cluster_from(vec![
            ("neighborhood-mode", "zero-hop", Set),
            ("chain", DEFAULT_CHAIN.rec().literal_identifier, Default),
            (
                "data-directory",
                &existing_data_dir.to_string_lossy().to_string(),
                Default,
            ),
        ]);
        let data_dir_referenced_from_the_home_dir = node_base_dir_relative_to_os_home_dir
            .join(new_dir_levels)
            .as_os_str()
            .to_str()
            .unwrap()
            .to_string();
        let incoming_setup = vec![
            (
                "data-directory",
                &format!("~/{}", data_dir_referenced_from_the_home_dir),
            ),
            (
                "config-file",
                &format!("~/{}/config.toml", data_dir_referenced_from_the_home_dir),
            ),
        ]
        .into_iter()
        .map(|(name, value)| UiSetupRequestValue::new(name, value))
        .collect_vec();
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .unwrap();

        let actual_config_file_data = result.get("blockchain-service-url").unwrap().value.as_str();
        assert_eq!(actual_config_file_data, "https://www.mainnet.com");
    }

    #[test]
    fn get_modified_setup_user_specified_data_directory_depends_on_new_chain_on_success() {
        let _guard = EnvironmentGuard::new();
        let base_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_user_specified_data_directory_depends_on_new_chain_on_success",
        );
        let data_dir = base_dir.join("data_dir");
        let previously_processed_data_dir = data_dir.join(DEFAULT_CHAIN.rec().literal_identifier);
        let existing_setup = setup_cluster_from(vec![
            ("neighborhood-mode", "zero-hop", Set),
            ("chain", DEFAULT_CHAIN.rec().literal_identifier, Default),
            (
                "data-directory",
                &previously_processed_data_dir.to_string_lossy().to_string(),
                Set,
            ),
            ("real-user", &format!("1000:1000:{:?}", base_dir), Default),
        ]);
        let incoming_setup = vec![("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier)]
            .into_iter()
            .map(|(name, value)| UiSetupRequestValue::new(name, value))
            .collect_vec();
        let dirs_wrapper = Box::new(
            DirsWrapperMock::new()
                .data_dir_result(Some(data_dir.clone()))
                .home_dir_result(Some(base_dir)),
        );
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .unwrap();
        let actual_data_directory = PathBuf::from(&result.get("data-directory").unwrap().value);
        let expected_data_directory = data_dir.join(TEST_DEFAULT_CHAIN.rec().literal_identifier);

        assert_eq!(actual_data_directory, expected_data_directory);
    }

    #[test]
    fn get_modified_setup_data_directory_set_previously_and_now_too() {
        let _guard = EnvironmentGuard::new();
        let base_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_data_directory_set_previously_and_now_too",
        );
        let default_data_dir = base_dir.join("data_dir");
        let previously_processed_data_dir = default_data_dir
            .join("my_special_folder")
            .join(DEFAULT_CHAIN.rec().literal_identifier);
        let new_data_dir = base_dir.join("new_data_dir");
        let existing_setup = setup_cluster_from(vec![
            ("neighborhood-mode", "zero-hop", Set),
            ("chain", DEFAULT_CHAIN.rec().literal_identifier, Default),
            (
                "data-directory",
                &previously_processed_data_dir.to_string_lossy().to_string(),
                Set,
            ),
            ("real-user", &format!("1000:1000:{:?}", base_dir), Default),
        ]);
        let incoming_setup = vec![(
            "data-directory",
            &new_data_dir.to_string_lossy().to_string(),
        )]
        .into_iter()
        .map(|(name, value)| UiSetupRequestValue::new(name, value))
        .collect_vec();
        let expected_data_directory = new_data_dir.join(DEFAULT_CHAIN.rec().literal_identifier);
        let dirs_wrapper = Box::new(
            DirsWrapperMock::new()
                .data_dir_result(Some(default_data_dir))
                .home_dir_result(Some(base_dir)),
        );
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .unwrap();

        let actual_data_directory = PathBuf::from(&result.get("data-directory").unwrap().value);
        assert_eq!(actual_data_directory, expected_data_directory);
    }

    #[test]
    #[should_panic(
        expected = "broken code: data-directory value is neither in existing_setup or incoming_setup and yet this value \"blah/booga\" was found in the merged cluster"
    )]
    fn unreachable_variant_for_determine_tuple_for_data_directory_when_set() {
        let data_dir_value = UiSetupResponseValue::new("data-directory", "blah/booga", Set);

        let _ = SetupReporterReal::determine_setup_value_of_set_data_directory(
            &data_dir_value,
            None,
            None,
            DEFAULT_CHAIN,
        );
    }

    #[test]
    fn get_modified_setup_data_directory_depends_on_new_chain_on_error() {
        let _guard = EnvironmentGuard::new();
        let base_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_data_directory_depends_on_new_chain_on_error",
        );
        let current_data_dir = base_dir
            .join("MASQ")
            .join(DEFAULT_CHAIN.rec().literal_identifier);
        let existing_setup = setup_cluster_from(vec![
            ("blockchain-service-url", "", Required),
            ("chain", DEFAULT_CHAIN.rec().literal_identifier, Default),
            ("clandestine-port", "7788", Default),
            ("config-file", "config.toml", Default),
            ("consuming-private-key", "", Blank),
            (
                "data-directory",
                &current_data_dir.to_string_lossy().to_string(),
                Default,
            ),
            ("db-password", "", Required),
            ("dns-servers", "1.1.1.1", Default),
            (
                "earning-wallet",
                "0x47fb8671db83008d382c2e6ea67fa377378c0cea",
                Default,
            ),
            ("gas-price", "1", Default),
            ("ip", "1.2.3.4", Set),
            ("log-level", "warn", Default),
            ("neighborhood-mode", "zero-hop", Set),
            ("scans", "", Blank),
        ]);
        let incoming_setup = vec![("chain", TEST_DEFAULT_CHAIN.rec().literal_identifier)]
            .into_iter()
            .map(|(name, value)| UiSetupRequestValue::new(name, value))
            .collect_vec();
        let expected_data_directory = base_dir
            .join("MASQ")
            .join(TEST_DEFAULT_CHAIN.rec().literal_identifier);
        let dirs_wrapper = Box::new(
            DirsWrapperMock::new()
                .data_dir_result(Some(base_dir.clone()))
                .home_dir_result(Some(base_dir)),
        );
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .err()
            .unwrap()
            .0;

        let actual_data_directory = PathBuf::from(&result.get("data-directory").unwrap().value);
        assert_eq!(actual_data_directory, expected_data_directory);
    }

    #[test]
    fn get_modified_setup_blanking_chain_out_on_error_checking_chain_and_data_dir() {
        let _guard = EnvironmentGuard::new();
        let base_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_blanking_chain_out_on_error_checking_chain_and_data_dir",
        );
        let current_data_dir = base_dir
            .join("data_dir")
            .join("MASQ")
            .join(BlockChain::PolyAmoy.rec().literal_identifier); //not a default
        let existing_setup = setup_cluster_from(vec![
            ("blockchain-service-url", "", Required),
            ("chain", BlockChain::PolyAmoy.rec().literal_identifier, Set),
            ("clandestine-port", "7788", Default),
            ("config-file", "config.toml", Default),
            ("consuming-private-key", "", Blank),
            (
                "data-directory",
                &current_data_dir.to_string_lossy().to_string(),
                Default,
            ),
            ("db-password", "", Required),
            ("dns-servers", "1.1.1.1", Default),
            (
                "earning-wallet",
                "0x47fb8671db83008d382c2e6ea67fa377378c0cea",
                Default,
            ),
            ("gas-price", "1", Default),
            ("ip", "1.2.3.4", Set),
            ("log-level", "warn", Default),
            ("neighborhood-mode", "originate-only", Set),
            //this causes the error: cannot run in this mode without any supplied descriptors
            ("neighbors", "", Blank),
            ("real-user", &format!("1000:1000:{:?}", base_dir), Default),
            ("scans", "on", Default),
        ]);
        //blanking out the chain parameter
        let incoming_setup = vec![UiSetupRequestValue::clear("chain")];
        let base_data_dir = base_dir.join("data_dir");
        let dirs_wrapper = Box::new(
            DirsWrapperMock::new()
                .data_dir_result(Some(base_data_dir))
                .home_dir_result(Some(base_dir)),
        );
        let subject = SetupReporterReal::new(dirs_wrapper);

        let (resulting_setup_cluster, _) = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .unwrap_err();

        let expected_chain = PolyAmoy.rec().literal_identifier;
        let actual_chain = &resulting_setup_cluster.get("chain").unwrap().value;
        assert_eq!(actual_chain, expected_chain);
        let actual_data_directory =
            PathBuf::from(&resulting_setup_cluster.get("data-directory").unwrap().value);
        assert_eq!(actual_data_directory, current_data_dir);
    }

    #[test]
    fn get_modified_setup_does_not_support_database_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_setup_does_not_support_database_migration",
        );
        let conn = bring_db_0_back_to_life_and_return_connection(&data_dir.join(DATABASE_FILE));
        let dao = ConfigDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));
        let schema_version_before = dao.get("schema_version").unwrap().value_opt.unwrap();
        assert_eq!(schema_version_before, "0");
        let existing_setup = setup_cluster_from(vec![
            ("chain", DEFAULT_CHAIN.rec().literal_identifier, Default),
            (
                "data-directory",
                &data_dir.to_string_lossy().to_string(),
                Set,
            ),
            (
                "real-user",
                &crate::bootstrapper::RealUser::new(None, None, None)
                    .populate(&DirsWrapperReal::default())
                    .to_string(),
                Default,
            ),
        ]);
        let incoming_setup = vec![("ip", "1.2.3.4")]
            .into_iter()
            .map(|(name, value)| UiSetupRequestValue::new(name, value))
            .collect_vec();
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let _ = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .unwrap();

        let schema_version_after = dao.get("schema_version").unwrap().value_opt.unwrap();
        assert_eq!(schema_version_before, schema_version_after)
    }

    #[test]
    fn get_modified_blanking_something_that_should_not_be_blanked_fails_properly() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_modified_blanking_something_that_shouldnt_be_blanked_fails_properly",
        );
        let existing_setup = setup_cluster_from(vec![
            ("data-directory", home_dir.to_str().unwrap(), Set),
            ("neighborhood-mode", "originate-only", Set),
            (
                "neighbors",
                "masq://eth-mainnet:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542",
                Set,
            ),
        ]);
        let incoming_setup = vec![UiSetupRequestValue::clear("neighbors")];
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(existing_setup, incoming_setup)
            .err()
            .unwrap();

        assert_eq!(
            result.0.get("neighbors").unwrap().clone(),
            UiSetupResponseValue::new(
                "neighbors",
                "masq://eth-mainnet:gBviQbjOS3e5ReFQCvIhUM3i02d1zPleo1iXg_EN6zQ@86.75.30.9:5542",
                Set
            )
        );
    }

    #[test]
    fn run_configuration_without_existing_database_implies_config_dao_null_to_be_used() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "run_configuration_without_existing_database_implies_config_dao_null_to_be_used",
        );
        let current_default_gas_price = DEFAULT_GAS_PRICE;
        let gas_price_for_set_attempt = current_default_gas_price + 78;
        let multi_config =
            make_simplified_multi_config(["--data-directory", home_dir.to_str().unwrap()]);
        let dirs_wrapper = make_pre_populated_mocked_directory_wrapper();
        let subject = SetupReporterReal::new(Box::new(dirs_wrapper));

        let ((bootstrapper_config, mut persistent_config), _) =
            subject.run_configuration(&multi_config, &home_dir);

        let error = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::panic_on_migration())
            .unwrap_err();
        assert_eq!(error, InitializationError::Nonexistent);
        assert_eq!(
            bootstrapper_config.blockchain_bridge_config.gas_price,
            current_default_gas_price
        );
        persistent_config
            .set_gas_price(gas_price_for_set_attempt)
            .unwrap();
        //if this had contained ConfigDaoReal the setting would've worked
        let gas_price = persistent_config.gas_price().unwrap();
        //asserting negation
        assert_ne!(gas_price, gas_price_for_set_attempt);
    }

    #[test]
    fn run_configuration_suppresses_db_migration_which_implies_just_use_of_config_dao_null() {
        let data_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "run_configuration_suppresses_db_migration_which_implies_just_use_of_config_dao_null",
        );
        let current_default_gas_price = DEFAULT_GAS_PRICE;
        let gas_price_to_be_in_the_real_db = current_default_gas_price + 55;
        let gas_price_for_set_attempt = current_default_gas_price + 66;
        let conn = bring_db_0_back_to_life_and_return_connection(&data_dir.join(DATABASE_FILE));
        conn.execute(
            "update config set value = ? where name = 'gas_price'",
            [&gas_price_to_be_in_the_real_db],
        )
        .unwrap();
        let dao = ConfigDaoReal::new(Box::new(ConnectionWrapperReal::new(conn)));
        let updated_gas_price = dao.get("gas_price").unwrap().value_opt.unwrap();
        assert_eq!(
            updated_gas_price,
            gas_price_to_be_in_the_real_db.to_string()
        );
        let schema_version_before = dao.get("schema_version").unwrap().value_opt.unwrap();
        assert_eq!(schema_version_before, "0");
        let multi_config =
            make_simplified_multi_config(["--data-directory", data_dir.to_str().unwrap()]);
        let dirs_wrapper = make_pre_populated_mocked_directory_wrapper();
        let subject = SetupReporterReal::new(Box::new(dirs_wrapper));

        let ((bootstrapper_config, mut persistent_config), _) =
            subject.run_configuration(&multi_config, &data_dir);

        let schema_version_after = dao.get("schema_version").unwrap().value_opt.unwrap();
        assert_eq!(schema_version_before, schema_version_after);
        //asserting negation
        assert_ne!(
            bootstrapper_config.blockchain_bridge_config.gas_price,
            gas_price_to_be_in_the_real_db
        );
        persistent_config
            .set_gas_price(gas_price_for_set_attempt)
            .unwrap();
        //if this had contained ConfigDaoReal the setting would've worked
        let gas_price = persistent_config.gas_price().unwrap();
        //asserting negation
        assert_ne!(gas_price, gas_price_for_set_attempt);
    }

    #[test]
    fn calculate_fundamentals_with_only_environment() {
        let _guard = EnvironmentGuard::new();
        vec![
            ("MASQ_CHAIN", TEST_DEFAULT_CHAIN.rec().literal_identifier),
            ("MASQ_DATA_DIRECTORY", "env_dir"),
            ("MASQ_REAL_USER", "9999:9999:booga"),
        ]
        .into_iter()
        .for_each(|(name, value)| std::env::set_var(name, value));
        let setup = setup_cluster_from(vec![]);

        let (real_user_opt, data_directory_opt, chain) =
            SetupReporterReal::calculate_fundamentals(&DirsWrapperReal::default(), &setup).unwrap();

        assert_eq!(
            real_user_opt,
            Some(crate::bootstrapper::RealUser::new(
                Some(9999),
                Some(9999),
                Some(PathBuf::from("booga"))
            ))
        );
        assert_eq!(data_directory_opt, Some(PathBuf::from("env_dir")));
        assert_eq!(chain, TEST_DEFAULT_CHAIN);
    }

    #[test]
    fn calculate_fundamentals_with_environment_and_obsolete_setup() {
        let _guard = EnvironmentGuard::new();
        vec![
            ("MASQ_CHAIN", TEST_DEFAULT_CHAIN.rec().literal_identifier),
            ("MASQ_DATA_DIRECTORY", "env_dir"),
            ("MASQ_REAL_USER", "9999:9999:booga"),
        ]
        .into_iter()
        .for_each(|(name, value)| std::env::set_var(name, value));
        let setup = setup_cluster_from(vec![
            ("chain", "dev", Configured),
            ("data-directory", "setup_dir", Default),
            ("real-user", "1111:1111:agoob", Configured),
        ]);

        let (real_user_opt, data_directory_opt, chain) =
            SetupReporterReal::calculate_fundamentals(&DirsWrapperReal::default(), &setup).unwrap();

        assert_eq!(
            real_user_opt,
            Some(crate::bootstrapper::RealUser::new(
                Some(9999),
                Some(9999),
                Some(PathBuf::from("booga"))
            ))
        );
        assert_eq!(data_directory_opt, Some(PathBuf::from("env_dir")));
        assert_eq!(chain, TEST_DEFAULT_CHAIN);
    }

    #[test]
    fn calculate_fundamentals_with_environment_and_overriding_setup() {
        let _guard = EnvironmentGuard::new();
        vec![
            ("MASQ_CHAIN", TEST_DEFAULT_CHAIN.rec().literal_identifier),
            ("MASQ_DATA_DIRECTORY", "env_dir"),
            ("MASQ_REAL_USER", "9999:9999:booga"),
        ]
        .into_iter()
        .for_each(|(name, value)| std::env::set_var(name, value));
        let setup = setup_cluster_from(vec![
            ("chain", "dev", Set),
            ("data-directory", "setup_dir", Set),
            ("real-user", "1111:1111:agoob", Set),
        ]);

        let (real_user_opt, data_directory_opt, chain) =
            SetupReporterReal::calculate_fundamentals(&DirsWrapperReal::default(), &setup).unwrap();

        assert_eq!(
            real_user_opt,
            Some(crate::bootstrapper::RealUser::new(
                Some(1111),
                Some(1111),
                Some(PathBuf::from("agoob"))
            ))
        );
        assert_eq!(data_directory_opt, Some(PathBuf::from("setup_dir")));
        assert_eq!(chain, Blockchain::from("dev"));
    }

    #[test]
    fn calculate_fundamentals_with_setup_and_no_environment() {
        let _guard = EnvironmentGuard::new();
        vec![]
            .into_iter()
            .for_each(|(name, value): (&str, &str)| std::env::set_var(name, value));
        let setup = setup_cluster_from(vec![
            ("chain", "dev", Configured),
            ("data-directory", "setup_dir", Default),
            ("real-user", "1111:1111:agoob", Configured),
        ]);

        let (real_user_opt, data_directory_opt, chain) =
            SetupReporterReal::calculate_fundamentals(&DirsWrapperReal::default(), &setup).unwrap();

        assert_eq!(
            real_user_opt,
            Some(crate::bootstrapper::RealUser::new(
                Some(1111),
                Some(1111),
                Some(PathBuf::from("agoob"))
            ))
        );
        assert_eq!(data_directory_opt, None);
        assert_eq!(chain, Blockchain::from("dev"));
    }

    #[test]
    fn calculate_fundamentals_with_neither_setup_nor_environment() {
        let _guard = EnvironmentGuard::new();
        vec![]
            .into_iter()
            .for_each(|(name, value): (&str, &str)| std::env::set_var(name, value));
        let setup = setup_cluster_from(vec![]);

        let (real_user_opt, data_directory_opt, chain) =
            SetupReporterReal::calculate_fundamentals(&DirsWrapperReal::default(), &setup).unwrap();

        assert_eq!(
            real_user_opt,
            Some(
                crate::bootstrapper::RealUser::new(None, None, None)
                    .populate(&DirsWrapperReal::default())
            )
        );
        assert_eq!(data_directory_opt, None);
        assert_eq!(chain, DEFAULT_CHAIN);
    }

    #[test]
    fn blanking_a_parameter_with_a_default_produces_that_default() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "blanking_a_parameter_with_a_default_produces_that_default",
        );
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject
            .get_modified_setup(
                HashMap::new(),
                vec![
                    UiSetupRequestValue::new(
                        "data-directory",
                        &home_dir.to_string_lossy().to_string(),
                    ),
                    UiSetupRequestValue::new("ip", "1.2.3.4"),
                    UiSetupRequestValue::clear("chain"),
                ],
            )
            .unwrap();

        let actual_chain = result.get("chain").unwrap();
        assert_eq!(
            actual_chain,
            &UiSetupResponseValue::new("chain", DEFAULT_CHAIN.rec().literal_identifier, Default)
        );
    }

    #[test]
    fn choose_uisrv_chooses_higher_priority_incoming_over_lower_priority_existing() {
        let existing = UiSetupResponseValue::new("name", "existing", Configured);
        let incoming = UiSetupResponseValue::new("name", "incoming", Set);

        let result = SetupReporterReal::choose_uisrv(&existing, &incoming);

        assert_eq!(result, &incoming);
    }

    #[test]
    fn choose_uisrv_chooses_higher_priority_existing_over_lower_priority_incoming() {
        let existing = UiSetupResponseValue::new("name", "existing", Set);
        let incoming = UiSetupResponseValue::new("name", "incoming", Configured);

        let result = SetupReporterReal::choose_uisrv(&existing, &incoming);

        assert_eq!(result, &existing);
    }

    #[test]
    fn choose_uisrv_chooses_incoming_over_existing_for_equal_priority() {
        let existing = UiSetupResponseValue::new("name", "existing", Set);
        let incoming = UiSetupResponseValue::new("name", "incoming", Set);

        let result = SetupReporterReal::choose_uisrv(&existing, &incoming);

        assert_eq!(result, &incoming);
    }

    #[test]
    fn config_file_not_specified_and_nonexistent() {
        let data_directory = ensure_node_home_directory_exists(
            "setup_reporter",
            "config_file_not_specified_and_nonexistent",
        );
        let setup = vec![
            // no config-file setting
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
            UiSetupResponseValue::new(
                "data-directory",
                &data_directory.to_string_lossy().to_string(),
                Set,
            ),
        ]
        .into_iter()
        .map(|uisrv| (uisrv.name.clone(), uisrv))
        .collect();
        let subject = SetupReporterReal::new(Box::new(DirsWrapperReal::default()));

        let result = subject
            .calculate_configured_setup(&setup, &data_directory)
            .0;

        assert_eq!(result.get("config-file").unwrap().value, "".to_string());
        assert_eq!(
            result.get("gas-price").unwrap().value,
            GasPrice {}
                .computed_default(
                    &BootstrapperConfig::new(),
                    &make_persistent_config_real_with_config_dao_null(),
                    &None
                )
                .unwrap()
                .0
        );
    }

    #[test]
    fn config_file_not_specified_but_exists() {
        let data_directory = ensure_node_home_directory_exists(
            "setup_reporter",
            "config_file_not_specified_but_exists",
        );
        {
            let config_file_path = data_directory.join("config.toml");
            create_dir_all(&data_directory)
                .expect("Could not create chain directory inside config_file_not_specified_but_exists home/MASQ directory");
            let mut config_file = File::create(config_file_path).unwrap();
            config_file.write_all(b"gas-price = \"10\"\n").unwrap();
        }
        let setup = vec![
            // no config-file setting
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
            UiSetupResponseValue::new(
                "data-directory",
                &data_directory.to_string_lossy().to_string(),
                Set,
            ),
        ]
        .into_iter()
        .map(|uisrv| (uisrv.name.clone(), uisrv))
        .collect();

        let (result, _) = SetupReporterReal::new(Box::new(DirsWrapperReal::default()))
            .calculate_configured_setup(&setup, &*data_directory);

        assert_eq!(result.get("gas-price").unwrap().value, "10".to_string());
    }

    #[test]
    fn config_file_has_relative_directory_that_exists_in_data_directory() {
        let data_directory = ensure_node_home_directory_exists(
            "setup_reporter",
            "config_file_has_relative_directory_that_exists_in_data_directory",
        );
        {
            let config_file_dir = data_directory.join("booga");
            std::fs::create_dir_all(&config_file_dir).unwrap();
            let config_file_path = config_file_dir.join("special.toml");
            let mut config_file = File::create(config_file_path).unwrap();
            config_file.write_all(b"gas-price = \"10\"\n").unwrap();
        }
        let setup = vec![
            //no config-file setting
            UiSetupResponseValue::new("chain", "polygon-amoy", Set),
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
            UiSetupResponseValue::new("config-file", "booga/special.toml", Set),
            UiSetupResponseValue::new(
                "data-directory",
                &data_directory.to_string_lossy().to_string(),
                Set,
            ),
        ]
        .into_iter()
        .map(|uisrv| (uisrv.name.clone(), uisrv))
        .collect();
        let subject = SetupReporterReal::new(Box::new(DirsWrapperReal::default()));
        let result = subject
            .calculate_configured_setup(&setup, &data_directory)
            .0;
        assert_eq!(result.get("gas-price").unwrap().value, "10".to_string());
    }

    #[test]
    fn config_file_has_relative_directory_that_does_not_exist_in_data_directory() {
        let data_directory = ensure_node_home_directory_exists(
            "setup_reporter",
            "config_file_has_relative_directory_that_does_not_exist_in_data_directory",
        );
        let setup = vec![
            // no config-file setting
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
            UiSetupResponseValue::new("config-file", "booga/special.toml", Set),
            UiSetupResponseValue::new(
                "data-directory",
                &data_directory.to_string_lossy().to_string(),
                Set,
            ),
        ]
        .into_iter()
        .map(|uisrv| (uisrv.name.clone(), uisrv))
        .collect();
        let subject = SetupReporterReal::new(Box::new(DirsWrapperReal::default()));

        let result = subject
            .calculate_configured_setup(&setup, &data_directory)
            .1
            .unwrap();

        assert_eq!(result.param_errors[0].parameter, "config-file");
        assert_string_contains(&result.param_errors[0].reason, "Are you sure it exists?");
    }

    #[test]
    fn config_file_has_absolute_path_to_file_that_exists() {
        let data_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "config_file_has_absolute_path_to_file_that_exists",
        )
        .canonicalize()
        .unwrap();
        let config_file_dir = data_dir.join("data_dir").join("my_config_file");
        std::fs::create_dir_all(&config_file_dir).unwrap();
        let config_file_path = config_file_dir.join("special.toml");
        {
            let mut config_file = File::create(config_file_path.clone()).unwrap();
            config_file.write_all(b"gas-price = \"10\"\n").unwrap();
        }
        let setup = vec![
            // no config-file setting
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
            UiSetupResponseValue::new(
                "config-file",
                &config_file_path.to_string_lossy().to_string(),
                Set,
            ),
        ]
        .into_iter()
        .map(|uisrv| (uisrv.name.clone(), uisrv))
        .collect();
        let subject = SetupReporterReal::new(Box::new(DirsWrapperReal::default()));

        let result = subject.calculate_configured_setup(&setup, &data_dir).0;

        assert_eq!(result.get("gas-price").unwrap().value, "10".to_string());
    }

    #[test]
    fn config_file_has_absolute_path_to_file_that_does_not_exist() {
        let config_file_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "config_file_has_absolute_path_to_file_that_does_not_exist",
        );
        let config_file_dir = config_file_dir.canonicalize().unwrap();
        let config_file_path = config_file_dir.join("nonexistent.toml");
        let wrapper = DirsWrapperReal::default();
        let data_directory = wrapper
            .data_dir()
            .unwrap()
            .join("MASQ")
            .join(DEFAULT_CHAIN.rec().literal_identifier);
        let setup = vec![
            // no config-file setting
            UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
            UiSetupResponseValue::new(
                "config-file",
                &config_file_path.to_string_lossy().to_string(),
                Set,
            ),
        ]
        .into_iter()
        .map(|uisrv| (uisrv.name.clone(), uisrv))
        .collect();
        let subject = SetupReporterReal::new(Box::new(DirsWrapperReal::default()));

        let result = subject
            .calculate_configured_setup(&setup, &data_directory)
            .1
            .unwrap();

        assert_eq!(result.param_errors[0].parameter, "config-file");
        assert_string_contains(&result.param_errors[0].reason, "Are you sure it exists?");
    }

    #[test]
    fn chain_computed_default() {
        let subject = Chain {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(
            result,
            Some((DEFAULT_CHAIN.rec().literal_identifier.to_string(), Default))
        );
    }

    #[test]
    fn clandestine_port_computed_default_present() {
        let persistent_config =
            PersistentConfigurationMock::new().clandestine_port_result(Ok(1234));
        let subject = ClandestinePort {};

        let result =
            subject.computed_default(&BootstrapperConfig::new(), &persistent_config, &None);

        assert_eq!(result, Some(("1234".to_string(), Configured)))
    }

    #[test]
    fn clandestine_port_database_field_error() {
        let subject = ClandestinePort {};
        let persistent_config = PersistentConfigurationMock::new()
            .clandestine_port_result(Err(PersistentConfigError::NotPresent));

        let result =
            subject.computed_default(&BootstrapperConfig::new(), &persistent_config, &None);

        assert_eq!(result, None)
    }

    #[test]
    fn data_directory_computed_default() {
        let real_user = RealUser::new(None, None, None).populate(&DirsWrapperReal::default());
        let expected = data_directory_from_context(
            &DirsWrapperReal::default(),
            &real_user,
            Blockchain::EthMainnet,
        )
        .to_string_lossy()
        .to_string();
        let mut config = BootstrapperConfig::new();
        config.real_user = real_user;
        config.blockchain_bridge_config.chain = Blockchain::from("eth-mainnet");

        let subject = DataDirectory::default();

        let result = subject.computed_default(
            &config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some((expected, Default)))
    }

    #[test]
    fn dns_servers_computed_default_does_not_exist_when_platform_is_not_recognized() {
        let factory = DnsModifierFactoryMock::new().make_result(None);
        let mut subject = DnsServers::new();
        subject.factory = Box::new(factory);

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, None)
    }

    #[test]
    fn dns_servers_computed_default_does_not_exist_when_dns_is_subverted() {
        let modifier = DnsInspectorMock::new()
            .inspect_result(Ok(vec![IpAddr::from_str("127.0.0.1").unwrap()]));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(modifier)));
        let mut subject = DnsServers::new();
        subject.factory = Box::new(factory);

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, None)
    }

    #[test]
    fn dns_servers_computed_default_does_not_exist_when_dns_inspection_fails() {
        init_test_logging();
        let modifier =
            DnsInspectorMock::new().inspect_result(Err(DnsInspectionError::NotConnected));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(modifier)));
        let mut subject = DnsServers::new();
        subject.factory = Box::new(factory);

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing("WARN: DnsServers: Error inspecting DNS settings: This system does not appear to be connected to a network");
    }

    #[test]
    fn dns_servers_computed_default_does_not_exist_when_dns_inspection_returns_no_addresses() {
        let modifier = DnsInspectorMock::new().inspect_result(Ok(vec![]));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(modifier)));
        let mut subject = DnsServers::new();
        subject.factory = Box::new(factory);

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, None)
    }

    #[test]
    fn dns_servers_computed_default_exists_when_dns_inspection_succeeds() {
        let modifier = DnsInspectorMock::new().inspect_result(Ok(vec![
            IpAddr::from_str("192.168.0.1").unwrap(),
            IpAddr::from_str("8.8.8.8").unwrap(),
        ]));
        let factory = DnsModifierFactoryMock::new().make_result(Some(Box::new(modifier)));
        let mut subject = DnsServers::new();
        subject.factory = Box::new(factory);

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("192.168.0.1,8.8.8.8".to_string(), Default)))
    }

    #[test]
    fn earning_wallet_computed_default_with_everything_configured_is_still_none() {
        let mut config = BootstrapperConfig::new();
        config.earning_wallet = Wallet::new("command-line address");
        let persistent_config = PersistentConfigurationMock::new()
            .earning_wallet_address_result(Ok(Some("persistent address".to_string())));
        let subject = EarningWallet {};

        let result = subject.computed_default(&config, &persistent_config, &None);

        assert_eq!(result, None)
    }

    #[test]
    fn earning_wallet_computed_default_with_nothing_configured_is_still_none() {
        let config = BootstrapperConfig::new();
        let subject = EarningWallet {};

        let result = subject.computed_default(
            &config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, None)
    }

    #[test]
    fn gas_price_computed_default_present() {
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.blockchain_bridge_config.gas_price = 57;
        let subject = GasPrice {};

        let result = subject.computed_default(
            &bootstrapper_config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("57".to_string(), Default)))
    }

    #[test]
    fn gas_price_computed_default_absent() {
        let subject = GasPrice {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("1".to_string(), Default)))
    }

    #[test]
    fn ip_computed_default_when_automap_works_and_neighborhood_mode_is_not_standard() {
        let subject = Ip {};
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config.mode = crate::sub_lib::neighborhood::NeighborhoodMode::ZeroHop;

        let result = subject.computed_default(
            &config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("".to_string(), Blank)));
    }

    #[test]
    fn ip_computed_default_when_neighborhood_mode_is_standard() {
        let subject = Ip {};
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config.mode = crate::sub_lib::neighborhood::NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("5.6.7.8").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );

        let result = subject.computed_default(
            &config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("5.6.7.8".to_string(), Set)));
    }

    #[test]
    fn ip_computed_default_when_automap_does_not_work_and_neighborhood_mode_is_not_standard() {
        let subject = Ip {};
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config.mode = crate::sub_lib::neighborhood::NeighborhoodMode::ZeroHop;

        let result = subject.computed_default(
            &config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("".to_string(), Blank)));
    }

    #[test]
    fn log_level_computed_default() {
        let subject = LogLevel {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("warn".to_string(), Default)))
    }

    #[test]
    fn mapping_protocol_is_just_blank_if_no_data_in_database() {
        let subject = MappingProtocol {};
        let persistent_config =
            PersistentConfigurationMock::default().mapping_protocol_result(Ok(None));

        let result =
            subject.computed_default(&BootstrapperConfig::new(), &persistent_config, &None);

        assert_eq!(result, None)
    }

    #[test]
    fn mapping_protocol_is_configured_if_data_in_database() {
        let subject = MappingProtocol {};
        let persistent_config = PersistentConfigurationMock::default()
            .mapping_protocol_result(Ok(Some(AutomapProtocol::Pmp)));
        let bootstrapper_config = BootstrapperConfig::new();

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(result, Some(("pmp".to_string(), Configured)))
    }

    #[test]
    fn min_hops_computes_default_from_value_in_database() {
        let subject = MinHops::new();
        let value_in_db = Hops::TwoHops;
        let persistent_config =
            PersistentConfigurationMock::default().min_hops_result(Ok(value_in_db));
        let bootstrapper_config = BootstrapperConfig::new();

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(result, Some((value_in_db.to_string(), Configured)))
    }

    #[test]
    fn min_hops_will_log_an_error_if_no_value_is_found_in_db() {
        init_test_logging();
        let subject = MinHops::new();
        let persistent_config = PersistentConfigurationMock::default()
            .min_hops_result(Err(PersistentConfigError::NotPresent));
        let bootstrapper_config = BootstrapperConfig::new();

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(result, None);
        TestLogHandler::new().exists_log_containing(
            "ERROR: MinHops: No value for min hops found in database; \
            database is corrupt: NotPresent",
        );
    }

    #[test]
    fn neighborhood_mode_computed_default() {
        let subject = NeighborhoodMode {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, Some(("standard".to_string(), Default)))
    }

    #[test]
    fn neighbors_computed_default_persistent_config_present_password_present_values_present() {
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .past_neighbors_params(&past_neighbors_params_arc)
            .past_neighbors_result(Ok(Some(vec![
                NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-mainnet:MTEyMjMzNDQ1NTY2Nzc4ODExMjIzMzQ0NTU2Njc3ODg@1.2.3.4:1234",
                ))
                .unwrap(),
                NodeDescriptor::try_from((
                    main_cryptde(),
                    "masq://eth-mainnet:ODg3NzY2NTU0NDMzMjIxMTg4Nzc2NjU1NDQzMzIyMTE@4.3.2.1:4321",
                ))
                .unwrap(),
            ])));
        let subject = Neighbors {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &persistent_config,
            &Some("password".to_string()),
        );

        assert_eq! (result, Some (("masq://eth-mainnet:MTEyMjMzNDQ1NTY2Nzc4ODExMjIzMzQ0NTU2Njc3ODg@1.2.3.4:1234,masq://eth-mainnet:ODg3NzY2NTU0NDMzMjIxMTg4Nzc2NjU1NDQzMzIyMTE@4.3.2.1:4321".to_string(), Configured)));
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(*past_neighbors_params, vec!["password".to_string()])
    }

    #[test]
    fn neighbors_computed_default_persistent_config_present_password_present_values_absent() {
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .past_neighbors_params(&past_neighbors_params_arc)
            .past_neighbors_result(Ok(None));
        let subject = Neighbors {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &persistent_config,
            &Some("password".to_string()),
        );

        assert_eq!(result, None);
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(*past_neighbors_params, vec!["password".to_string()])
    }

    #[test]
    fn neighbors_computed_default_persistent_config_present_password_present_but_with_err() {
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .past_neighbors_params(&past_neighbors_params_arc)
            .past_neighbors_result(Err(PersistentConfigError::PasswordError));
        let subject = Neighbors {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &persistent_config,
            &Some("password".to_string()),
        );

        assert_eq!(result, None);
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(*past_neighbors_params, vec!["password".to_string()])
    }

    #[test]
    fn neighbors_computed_default_persistent_config_present_password_absent() {
        // absence of configured result will cause panic if past_neighbors is called
        let persistent_config = PersistentConfigurationMock::new();
        let subject = Neighbors {};

        let result =
            subject.computed_default(&BootstrapperConfig::new(), &persistent_config, &None);

        assert_eq!(result, None);
    }

    #[test]
    fn neighbors_computed_default_absent() {
        let subject = Neighbors {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, None);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn real_user_computed_default() {
        let subject = crate::daemon::setup_reporter::RealUser::default();

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(
            result,
            Some((
                RealUser::new(None, None, None)
                    .populate(&DirsWrapperReal::default())
                    .to_string(),
                Default
            ))
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn real_user_computed_default() {
        let subject = crate::daemon::setup_reporter::RealUser::default();

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(result, None);
    }

    fn assert_rate_pack_computed_default_advanced_evaluation_regarding_specific_neighborhood(
        neighborhood_mode: fn(rate_pack: neighborhood::RatePack) -> NeighborhoodModeEnum,
    ) {
        let subject = RatePack {};
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.neighborhood_config.mode = neighborhood_mode(DEFAULT_RATE_PACK);
        let persistent_config =
            PersistentConfigurationReal::new(Box::new(ConfigDaoNull::default()));

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(result, Some((DEFAULT_RATE_PACK.to_string(), Default)))
    }

    #[test]
    fn rate_pack_computed_default_when_persistent_config_like_default() {
        assert_computed_default_when_persistent_config_like_default(
            &RatePack {},
            DEFAULT_RATE_PACK.to_string(),
        )
    }

    #[test]
    fn rate_pack_computed_default_persistent_config_unequal_to_default() {
        let mut rate_pack = DEFAULT_RATE_PACK;
        rate_pack.routing_byte_rate += 5;
        rate_pack.exit_service_rate += 6;

        assert_computed_default_when_persistent_config_unequal_to_default(
            &RatePack {},
            rate_pack,
            &|p_c: PersistentConfigurationMock, value: neighborhood::RatePack| {
                p_c.rate_pack_result(Ok(value))
            },
        )
    }

    #[test]
    fn rate_pack_computed_default_neighborhood_mode_diff_from_standard_or_originate_only_returns_none(
    ) {
        let subject = &RatePack {};
        let mut bootstrapper_config = BootstrapperConfig::new();
        let consume_only = NeighborhoodModeEnum::ConsumeOnly(vec![]);
        bootstrapper_config.neighborhood_config.mode = consume_only;
        let persistent_config =
            PersistentConfigurationReal::new(Box::new(ConfigDaoNull::default()));

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(result, None);
        let zero_hop = NeighborhoodModeEnum::ZeroHop;
        bootstrapper_config.neighborhood_config.mode = zero_hop;
        let persistent_config =
            PersistentConfigurationReal::new(Box::new(ConfigDaoNull::default()));

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(result, None);
    }

    #[test]
    fn scans_computed_default() {
        let subject = Scans {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &PersistentConfigurationMock::new(),
            &None,
        );

        assert_eq!(result, Some(("on".to_string(), Default)));
    }

    #[test]
    fn rate_pack_standard_mode_goes_on_with_further_evaluation() {
        assert_rate_pack_computed_default_advanced_evaluation_regarding_specific_neighborhood(
            |rate_pack: neighborhood::RatePack| {
                NeighborhoodModeEnum::Standard(
                    NodeAddr::new(&IpAddr::from_str("4.5.6.7").unwrap(), &[44444]),
                    vec![],
                    rate_pack,
                )
            },
        );
    }

    #[test]
    fn rate_pack_originate_only_mode_goes_on_with_further_evaluation() {
        assert_rate_pack_computed_default_advanced_evaluation_regarding_specific_neighborhood(
            |rate_pack: neighborhood::RatePack| {
                NeighborhoodModeEnum::OriginateOnly(vec![], rate_pack)
            },
        );
    }

    #[test]
    fn scan_intervals_computed_default_when_persistent_config_like_default() {
        assert_computed_default_when_persistent_config_like_default(
            &ScanIntervals {},
            *DEFAULT_SCAN_INTERVALS,
        )
    }

    #[test]
    fn scan_intervals_computed_default_persistent_config_unequal_to_default() {
        let mut scan_intervals = *DEFAULT_SCAN_INTERVALS;
        scan_intervals.pending_payable_scan_interval = scan_intervals
            .pending_payable_scan_interval
            .add(Duration::from_secs(15));
        scan_intervals.pending_payable_scan_interval = scan_intervals
            .receivable_scan_interval
            .sub(Duration::from_secs(33));

        assert_computed_default_when_persistent_config_unequal_to_default(
            &ScanIntervals {},
            scan_intervals,
            &|p_c: PersistentConfigurationMock, value: accountant::ScanIntervals| {
                p_c.scan_intervals_result(Ok(value))
            },
        )
    }

    #[test]
    fn payment_thresholds_computed_default_when_persistent_config_like_default() {
        assert_computed_default_when_persistent_config_like_default(
            &PaymentThresholds {},
            DEFAULT_PAYMENT_THRESHOLDS.to_string(),
        )
    }

    #[test]
    fn payment_thresholds_computed_default_persistent_config_unequal_to_default() {
        let mut payment_thresholds = PaymentThresholdsFromAccountant::default();
        payment_thresholds.maturity_threshold_sec += 12;
        payment_thresholds.unban_below_gwei -= 12;
        payment_thresholds.debt_threshold_gwei += 1111;

        assert_computed_default_when_persistent_config_unequal_to_default(
            &PaymentThresholds {},
            payment_thresholds,
            &|p_c: PersistentConfigurationMock, value: accountant::PaymentThresholds| {
                p_c.payment_thresholds_result(Ok(value))
            },
        )
    }

    fn assert_computed_default_when_persistent_config_like_default<T>(
        subject: &dyn ValueRetriever,
        default: T,
    ) where
        T: Display + PartialEq,
    {
        let mut bootstrapper_config = BootstrapperConfig::new();
        //the rate_pack within the mode setting does not determine the result, so I just set a nonsense
        bootstrapper_config.neighborhood_config.mode =
            NeighborhoodModeEnum::OriginateOnly(vec![], rate_pack(0));
        let persistent_config =
            PersistentConfigurationReal::new(Box::new(ConfigDaoNull::default()));

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(result, Some((default.to_string(), Default)))
    }

    fn assert_computed_default_when_persistent_config_unequal_to_default<T, C>(
        subject: &dyn ValueRetriever,
        persistent_config_value: T,
        pc_method_result_setter: &C,
    ) where
        C: Fn(PersistentConfigurationMock, T) -> PersistentConfigurationMock,
        T: Display + PartialEq + Clone,
    {
        let mut bootstrapper_config = BootstrapperConfig::new();
        //the rate_pack within the mode setting does not determine the result, so I just set a nonsense
        bootstrapper_config.neighborhood_config.mode =
            NeighborhoodModeEnum::OriginateOnly(vec![], rate_pack(0));
        let persistent_config = pc_method_result_setter(
            PersistentConfigurationMock::new(),
            persistent_config_value.clone(),
        );

        let result = subject.computed_default(&bootstrapper_config, &persistent_config, &None);

        assert_eq!(
            result,
            Some((persistent_config_value.to_string(), Configured))
        )
    }

    fn verify_requirements(
        subject: &dyn ValueRetriever,
        param_name: &str,
        value_predictions: Vec<(&str, bool)>,
    ) {
        value_predictions
            .into_iter()
            .for_each(|(param_value, prediction)| {
                let params = vec![(
                    param_name.to_string(),
                    UiSetupResponseValue::new(param_name, param_value, Set),
                )]
                .into_iter()
                .collect::<SetupCluster>();

                let result = subject.is_required(&params);

                assert_eq!(result, prediction, "{:?}", params);
            })
    }

    fn verify_needed_for_blockchain(subject: &dyn ValueRetriever) {
        verify_requirements(
            subject,
            "neighborhood-mode",
            vec![
                ("standard", true),
                ("zero-hop", false),
                ("originate-only", true),
                ("consume-only", true),
            ],
        );
    }

    #[test]
    fn ip_requirements() {
        verify_requirements(
            &Ip {},
            "neighborhood-mode",
            vec![
                ("standard", false),
                ("zero-hop", false),
                ("originate-only", false),
                ("consume-only", false),
            ],
        );
    }

    #[test]
    fn dnsservers_requirements() {
        verify_requirements(
            &DnsServers::new(),
            "neighborhood-mode",
            vec![
                ("standard", true),
                ("zero-hop", true),
                ("originate-only", true),
                ("consume-only", false),
            ],
        );
    }

    #[test]
    fn neighbors_requirements() {
        verify_requirements(
            &Neighbors {},
            "neighborhood-mode",
            vec![
                ("standard", false),
                ("zero-hop", false),
                ("originate-only", true),
                ("consume-only", true),
            ],
        );
    }

    #[test]
    fn blockchain_requirements() {
        verify_needed_for_blockchain(&BlockchainServiceUrl {});
        verify_needed_for_blockchain(&DbPassword {});
        verify_needed_for_blockchain(&GasPrice {});
    }

    #[test]
    fn routing_byte_rate_requirements() {
        verify_requirements(
            &setup_reporter::RatePack {},
            "neighborhood-mode",
            vec![
                ("standard", true),
                ("zero-hop", false),
                ("originate-only", true),
                ("consume-only", false),
            ],
        );
    }

    #[test]
    fn dumb_requirements() {
        let params = HashMap::new();
        assert_eq!(BlockchainServiceUrl {}.is_required(&params), true);
        assert_eq!(Chain {}.is_required(&params), true);
        assert_eq!(ClandestinePort {}.is_required(&params), true);
        assert_eq!(ConfigFile {}.is_required(&params), false);
        assert_eq!(ConsumingPrivateKey {}.is_required(&params), false);
        assert_eq!(DataDirectory::default().is_required(&params), true);
        assert_eq!(DbPassword {}.is_required(&params), true);
        assert_eq!(DnsServers::new().is_required(&params), true);
        assert_eq!(EarningWallet {}.is_required(&params), false);
        assert_eq!(GasPrice {}.is_required(&params), true);
        assert_eq!(Ip {}.is_required(&params), false);
        assert_eq!(LogLevel {}.is_required(&params), true);
        assert_eq!(MappingProtocol {}.is_required(&params), false);
        assert_eq!(MinHops::new().is_required(&params), false);
        assert_eq!(NeighborhoodMode {}.is_required(&params), true);
        assert_eq!(Neighbors {}.is_required(&params), true);
        assert_eq!(
            setup_reporter::PaymentThresholds {}.is_required(&params),
            true
        );
        assert_eq!(ScanIntervals {}.is_required(&params), true);
        assert_eq!(
            crate::daemon::setup_reporter::RealUser::default().is_required(&params),
            false
        );
        assert_eq!(Scans {}.is_required(&params), false);
    }

    #[test]
    fn value_retrievers_know_their_names() {
        assert_eq!(
            BlockchainServiceUrl {}.value_name(),
            "blockchain-service-url"
        );
        assert_eq!(Chain {}.value_name(), "chain");
        assert_eq!(ClandestinePort {}.value_name(), "clandestine-port");
        assert_eq!(ConfigFile {}.value_name(), "config-file");
        assert_eq!(ConsumingPrivateKey {}.value_name(), "consuming-private-key");
        assert_eq!(DataDirectory::default().value_name(), "data-directory");
        assert_eq!(DbPassword {}.value_name(), "db-password");
        assert_eq!(DnsServers::new().value_name(), "dns-servers");
        assert_eq!(EarningWallet {}.value_name(), "earning-wallet");
        assert_eq!(GasPrice {}.value_name(), "gas-price");
        assert_eq!(Ip {}.value_name(), "ip");
        assert_eq!(LogLevel {}.value_name(), "log-level");
        assert_eq!(MappingProtocol {}.value_name(), "mapping-protocol");
        assert_eq!(MinHops::new().value_name(), "min-hops");
        assert_eq!(NeighborhoodMode {}.value_name(), "neighborhood-mode");
        assert_eq!(Neighbors {}.value_name(), "neighbors");
        assert_eq!(
            setup_reporter::PaymentThresholds {}.value_name(),
            "payment-thresholds"
        );
        assert_eq!(setup_reporter::RatePack {}.value_name(), "rate-pack");
        assert_eq!(ScanIntervals {}.value_name(), "scan-intervals");
        assert_eq!(
            crate::daemon::setup_reporter::RealUser::default().value_name(),
            "real-user"
        );
        assert_eq!(Scans {}.value_name(), "scans");
    }

    #[test]
    fn calculate_setup_with_chain_specific_dir_on_user_specified_directory() {
        let _guard = EnvironmentGuard::new();
        let existing_setup =
            setup_cluster_from(vec![("real-user", "1111:1111:/home/booga", Default)]);
        let masqhome = Path::new("/home/booga/masqhome");
        let incoming_setup = vec![UiSetupRequestValue::new(
            "data-directory",
            &masqhome.to_str().unwrap(),
        )];
        let dirs_wrapper = Box::new(DirsWrapperReal::default());
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject.get_modified_setup(existing_setup, incoming_setup);

        let expected = masqhome.join("polygon-mainnet");
        assert_eq!(
            result.unwrap().get("data-directory").unwrap().value,
            expected.to_str().unwrap()
        );
    }

    #[test]
    fn calculate_setup_with_chain_specific_dir_on_default_directory() {
        let _guard = EnvironmentGuard::new();
        let existing_setup =
            setup_cluster_from(vec![("real-user", "1111:1111:/home/booga", Default)]);
        let incoming_setup = vec![UiSetupRequestValue::new("chain", "polygon-amoy")];
        let home_directory = Path::new("/home/booga");
        let data_directory = home_directory.join("data");
        let expected = data_directory.join("MASQ").join("polygon-amoy");
        let dirs_wrapper = Box::new(
            DirsWrapperMock::new()
                .data_dir_result(Some(data_directory))
                .home_dir_result(Some(home_directory.to_path_buf())),
        );
        let subject = SetupReporterReal::new(dirs_wrapper);

        let result = subject.get_modified_setup(existing_setup, incoming_setup);

        assert_eq!(
            result.unwrap().get("data-directory").unwrap().value,
            expected.to_str().unwrap()
        );
    }
}
