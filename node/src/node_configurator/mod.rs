// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod configurator;
pub mod node_configurator_initialization;
pub mod node_configurator_standard;
pub mod unprivileged_parse_args_configuration;

use crate::bootstrapper::RealUser;
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::utils::db_connection_launch_panic;
use clap::{value_t, App};
use core::option::Option;
use dirs::{data_local_dir, home_dir};
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::DEFAULT_CHAIN;
use masq_lib::multi_config::{merge, CommandLineVcl, EnvironmentVcl, MultiConfig, VclArg};
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::{add_masq_and_chain_directories, localhost};
use std::env::current_dir;
use std::net::{SocketAddr, TcpListener};
use std::ops::Deref;
use std::path::{Path, PathBuf};

pub trait NodeConfigurator<T> {
    fn configure(&self, multi_config: &MultiConfig) -> Result<T, ConfiguratorError>;
}

#[derive(Debug)]
pub struct UserSpecifiedData {
    pub(crate) chain: Chain,
    pub(crate) chain_spec: bool,
    pub(crate) real_user: RealUser,
    pub(crate) real_user_spec: bool,
    pub(crate) data_directory: PathBuf,
    pub(crate) data_directory_spec: bool,
    pub(crate) config_file: PathBuf,
    pub(crate) config_file_spec: bool,
}

fn get_chain_from_vcl(configs: &[Box<dyn VclArg>]) -> (Chain, bool) {
    match argument_from_enumerate(configs, "--chain") {
        Some(chain) => (Chain::from(chain), true),
        None => (DEFAULT_CHAIN, false),
    }
}

fn get_real_user_from_vcl(
    configs: &[Box<dyn VclArg>],
    dirs_wrapper: &dyn DirsWrapper,
) -> (RealUser, bool) {
    match argument_from_enumerate(configs, "--real-user") {
        Some(user) => {
            let real_user_split: Vec<&str> = user.split(':').collect();
            (
                RealUser::new(
                    Some(real_user_split[0].parse::<i32>().expect("expected user id")),
                    Some(
                        real_user_split[1]
                            .parse::<i32>()
                            .expect("expected user group"),
                    ),
                    Some(PathBuf::from(real_user_split[2])),
                ),
                true,
            )
        }
        None => (
            RealUser::new(None, None, None).populate(dirs_wrapper),
            false,
        ),
    }
}

fn get_data_directory_from_vcl(
    configs: &[Box<dyn VclArg>],
    dirs_wrapper: &dyn DirsWrapper,
    real_user: &RealUser,
    chain: &Chain,
) -> (PathBuf, bool) {
    match argument_from_enumerate(configs, "--data-directory") {
        Some(data_dir) => match PathBuf::from(data_dir).starts_with("~/") {
            true => {
                let home_dir_from_wrapper = dirs_wrapper
                    .home_dir()
                    .expect("expexted users home dir")
                    .to_str()
                    .expect("expect home dir")
                    .to_string();
                let replaced_tilde_dir =
                    data_dir
                        .to_string()
                        .replacen('~', home_dir_from_wrapper.as_str(), 1);
                (PathBuf::from(replaced_tilde_dir), true)
            }
            false => (PathBuf::from(&data_dir), true),
        },
        None => (
            data_directory_from_context(dirs_wrapper, real_user, *chain),
            false,
        ),
    }
}

fn get_config_file_from_vcl(
    configs: &[Box<dyn VclArg>],
    data_directory: &PathBuf,
    data_directory_def: bool,
    dirs_wrapper: &dyn DirsWrapper,
) -> (PathBuf, bool) {
    match argument_from_enumerate(configs, "--config-file") {
        Some(config_str) => {
            let path = match PathBuf::from(config_str).is_relative() {
                true => {
                    match PathBuf::from(config_str).file_name().expect("expected file name") == config_str {
                        true => PathBuf::from(data_directory).join(PathBuf::from(config_str)),
                        false => match PathBuf::from(config_str).starts_with("./") || PathBuf::from(config_str).starts_with("../") {
                            true => current_dir().expect("expected curerrnt dir").join(PathBuf::from(config_str)),
                            false => match PathBuf::from(config_str).starts_with("~") {
                                true => {
                                    let home_dir_from_wrapper = dirs_wrapper
                                        .home_dir()
                                        .expect("expexted users home dir")
                                        .to_str()
                                        .expect("expect home dir")
                                        .to_string();
                                    let replaced_tilde_dir =
                                        config_str
                                            .to_string()
                                            .replacen('~', home_dir_from_wrapper.as_str(), 1);
                                    PathBuf::from(replaced_tilde_dir)
                                }
                                false => match data_directory_def {
                                    true => PathBuf::from(data_directory).join(PathBuf::from(config_str)),
                                    false => panic!("You need to define data-directory to be able define config file with naked directory 'dirname/config.toml'.")
                                }
                            }
                        }
                    }
                }
                false => PathBuf::from(config_str),
            };
            (path, true)
        }
        None => {
            let path = PathBuf::from(data_directory).join(PathBuf::from("config.toml"));
            match path.is_file() {
                true => (path, true),
                false => (path, false),
            }
        }
    }
}

fn config_file_data_dir_real_user_chain_from_enumerate(
    dirs_wrapper: &dyn DirsWrapper,
    configs: Vec<Box<dyn VclArg>>,
) -> UserSpecifiedData {
    //TODO break down this function to collection of small one purpose functions
    let mut user_specified_data = UserSpecifiedData {
        chain: Default::default(),
        chain_spec: false,
        real_user: Default::default(),
        real_user_spec: false,
        data_directory: Default::default(),
        data_directory_spec: false,
        config_file: Default::default(),
        config_file_spec: false,
    };
    let configs = configs.as_slice();
    (user_specified_data.chain, user_specified_data.chain_spec) = get_chain_from_vcl(configs);
    (
        user_specified_data.real_user,
        user_specified_data.real_user_spec,
    ) = get_real_user_from_vcl(configs, dirs_wrapper);
    (
        user_specified_data.data_directory,
        user_specified_data.data_directory_spec,
    ) = get_data_directory_from_vcl(
        configs,
        dirs_wrapper,
        &user_specified_data.real_user,
        &user_specified_data.chain,
    );
    (
        user_specified_data.config_file,
        user_specified_data.config_file_spec,
    ) = get_config_file_from_vcl(
        configs,
        &user_specified_data.data_directory,
        user_specified_data.data_directory_spec,
        dirs_wrapper,
    );
    user_specified_data
}

fn argument_from_enumerate<'a>(configs: &'a [Box<dyn VclArg>], needle: &'a str) -> Option<&'a str> {
    match configs
        .iter()
        .find(|vcl_arg_box| vcl_arg_box.deref().name() == needle)
    {
        Some(vcl_arg_box) => vcl_arg_box.deref().value_opt(),
        None => None,
    }
}

pub fn determine_user_specific_data(
    dirs_wrapper: &dyn DirsWrapper,
    app: &App,
    args: &[String],
) -> Result<UserSpecifiedData, ConfiguratorError> {
    let orientation_args: Vec<Box<dyn VclArg>> = merge(
        Box::new(EnvironmentVcl::new(app)),
        Box::new(CommandLineVcl::new(args.to_vec())),
    )
    .vcl_args()
    .into_iter()
    .filter(|vcl_arg| {
        (vcl_arg.name() == "--chain")
            || (vcl_arg.name() == "--real-user")
            || (vcl_arg.name() == "--data-directory")
            || (vcl_arg.name() == "--config-file")
    })
    .map(|vcl_arg| vcl_arg.dup())
    .collect();
    let user_specified_data =
        config_file_data_dir_real_user_chain_from_enumerate(dirs_wrapper, orientation_args);

    Ok(user_specified_data)
}

pub fn initialize_database(
    data_directory: &Path,
    migrator_config: DbInitializationConfig,
) -> Box<dyn PersistentConfiguration> {
    let conn = DbInitializerReal::default()
        .initialize(data_directory, migrator_config)
        .unwrap_or_else(|e| db_connection_launch_panic(e, data_directory));
    Box::new(PersistentConfigurationReal::from(conn))
}

pub fn real_user_from_multi_config_or_populate(
    multi_config: &MultiConfig,
    dirs_wrapper: &dyn DirsWrapper,
) -> RealUser {
    match value_m!(multi_config, "real-user", RealUser) {
        None => RealUser::new(None, None, None).populate(dirs_wrapper),
        Some(real_user) => real_user.populate(dirs_wrapper),
    }
}

pub fn real_user_data_directory_path_and_chain(
    dirs_wrapper: &dyn DirsWrapper,
    multi_config: &MultiConfig,
) -> (RealUser, Option<PathBuf>, Chain) {
    let real_user = real_user_from_multi_config_or_populate(multi_config, dirs_wrapper);
    let chain_name = value_m!(multi_config, "chain", String)
        .unwrap_or_else(|| DEFAULT_CHAIN.rec().literal_identifier.to_string());
    let data_directory_path = value_m!(multi_config, "data-directory", PathBuf);
    (
        real_user,
        data_directory_path,
        Chain::from(chain_name.as_str()),
    )
}

pub fn data_directory_from_context(
    dirs_wrapper: &dyn DirsWrapper,
    real_user: &RealUser,
    chain: Chain,
) -> PathBuf {
    let right_home_dir = real_user
        .home_dir_opt
        .as_ref()
        .expect("No real-user home directory; specify --real-user");
    let wrong_home_dir = dirs_wrapper
        .home_dir()
        .expect("No privileged home directory; specify --data-directory");
    let wrong_local_data_dir = dirs_wrapper
        .data_dir()
        .expect("No privileged local data directory; specify --data-directory");
    let adjusted_local_data_dir: &Path = wrong_local_data_dir
        .strip_prefix(wrong_home_dir)
        .expect("std lib failed");
    let homedir = right_home_dir.join(adjusted_local_data_dir);
    add_masq_and_chain_directories(chain, &homedir)
}

pub fn port_is_busy(port: u16) -> bool {
    TcpListener::bind(SocketAddr::new(localhost(), port)).is_err()
}

pub trait DirsWrapper: Send {
    fn data_dir(&self) -> Option<PathBuf>;
    fn home_dir(&self) -> Option<PathBuf>;
    fn dup(&self) -> Box<dyn DirsWrapper>; // because implementing Clone for traits is problematic.
}

pub struct DirsWrapperReal;

impl DirsWrapper for DirsWrapperReal {
    fn data_dir(&self) -> Option<PathBuf> {
        data_local_dir()
    }
    fn home_dir(&self) -> Option<PathBuf> {
        home_dir()
    }
    fn dup(&self) -> Box<dyn DirsWrapper> {
        Box::new(DirsWrapperReal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_test_utils::DirsWrapperMock;
    use crate::test_utils::ArgsBuilder;
    use masq_lib::shared_schema::{config_file_arg, data_directory_arg, DATA_DIRECTORY_HELP};
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::find_free_port;
    use std::net::{SocketAddr, TcpListener};

    fn determine_config_file_path_app() -> App<'static, 'static> {
        App::new("test")
            .arg(data_directory_arg(DATA_DIRECTORY_HELP))
            .arg(config_file_arg())
    }

    #[test]
    fn data_directory_from_context_creates_new_folder_for_every_blockchain_platform() {
        let dirs_wrapper = DirsWrapperMock::new()
            .home_dir_result(Some(PathBuf::from("/nonexistent_home/root".to_string())))
            .data_dir_result(Some(PathBuf::from("/nonexistent_home/root/.local/share")));
        let real_user = RealUser::new(
            None,
            None,
            Some(PathBuf::from(
                "/nonexistent_home/nonexistent_alice".to_string(),
            )),
        );
        let chain_name = "polygon-mumbai";

        let result =
            data_directory_from_context(&dirs_wrapper, &real_user, Chain::from(chain_name));

        assert_eq!(
            result,
            PathBuf::from(
                "/nonexistent_home/nonexistent_alice/.local/share/MASQ/polygon-mumbai".to_string()
            )
        )
    }

    #[test]
    fn determine_config_file_path_finds_path_in_args() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "determine_config_file_path_finds_path_in_args",
        );
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--clandestine-port", "2345")
            .param(
                "--data-directory",
                &data_directory.to_string_lossy().to_string(),
            )
            .param("--config-file", "booga.toml");
        let args_vec: Vec<String> = args.into();

        let user_specific_data = determine_user_specific_data(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();
        assert_eq!(
            &format!(
                "{}",
                user_specific_data.config_file.parent().unwrap().display()
            ),
            &user_specific_data
                .data_directory
                .to_string_lossy()
                .to_string(),
        );
        assert_eq!(
            "booga.toml",
            user_specific_data.config_file.file_name().unwrap()
        );
        assert_eq!(user_specific_data.real_user_spec, false);
    }

    #[test]
    fn determine_config_file_path_finds_path_in_environment() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "determine_config_file_path_finds_path_in_environment",
        );
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new();
        let args_vec: Vec<String> = args.into();
        std::env::set_var(
            "MASQ_DATA_DIRECTORY",
            &data_directory.to_string_lossy().to_string(),
        );
        std::env::set_var("MASQ_CONFIG_FILE", "booga.toml");

        let user_specific_data = determine_user_specific_data(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();
        assert_eq!(
            format!(
                "{}",
                user_specific_data.config_file.parent().unwrap().display()
            ),
            user_specific_data
                .data_directory
                .to_string_lossy()
                .to_string(),
        );
        assert_eq!(
            "booga.toml",
            user_specific_data.config_file.file_name().unwrap()
        );
        assert_eq!(user_specific_data.real_user_spec, false); //all these assertions of 'real_user_specified' was incorrect, no idea how this tests could pass before
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", "/tmp/booga.toml");
        let args_vec: Vec<String> = args.into();

        let user_specific_data = determine_user_specific_data(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            "/tmp/booga.toml",
            &format!("{}", user_specific_data.config_file.display())
        );
        assert_eq!(user_specific_data.real_user_spec, false);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_separator_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"\tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let user_specific_data = determine_user_specific_data(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\tmp\booga.toml",
            &format!("{}", user_specific_data.config_file.display())
        );
        assert_eq!(user_specific_data.real_user_specified, false);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"c:\tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let user_specific_data = determine_user_specific_data(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:\tmp\booga.toml",
            &format!("{}", user_specific_data.config_file.display())
        );
        assert_eq!(user_specific_data.real_user_specified, false);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_network_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"\\TMP\booga.toml");
        let args_vec: Vec<String> = args.into();

        let user_specific_data = determine_user_specific_data(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\\TMP\booga.toml",
            &format!("{}", user_specific_data.config_file.display())
        );
        assert_eq!(user_specific_data.real_user_specified, false);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_letter_but_no_separator(
    ) {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"c:tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let user_specific_data = determine_user_specific_data(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:tmp\booga.toml",
            &format!("{}", user_specific_data.config_file.display())
        );
        assert_eq!(user_specific_data.real_user_specified, false);
    }

    #[test]
    pub fn port_is_busy_detects_free_port() {
        let port = find_free_port();

        let result = port_is_busy(port);

        assert_eq!(result, false);
    }

    #[test]
    pub fn port_is_busy_detects_busy_port() {
        let port = find_free_port();
        let _listener = TcpListener::bind(SocketAddr::new(localhost(), port)).unwrap();

        let result = port_is_busy(port);

        assert_eq!(result, true);
    }
}
