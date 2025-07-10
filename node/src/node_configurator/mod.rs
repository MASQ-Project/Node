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
use crate::sub_lib::utils::{db_connection_launch_panic, make_new_multi_config};
use clap::{value_t, App};
use core::option::Option;
use dirs::{data_local_dir, home_dir};
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::DEFAULT_CHAIN;
use masq_lib::multi_config::{
    merge, CommandLineVcl, EnvironmentVcl, MultiConfig, VirtualCommandLine,
};
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::{add_masq_and_chain_directories, localhost};
use std::env::current_dir;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

pub trait NodeConfigurator<T> {
    fn configure(&self, multi_config: &MultiConfig) -> Result<T, ConfiguratorError>;
}

#[derive(Default, Debug)]
pub struct FieldPair<T> {
    pub(crate) item: T,
    pub(crate) user_specified: bool,
}

impl<T> FieldPair<T> {
    fn new(item: T, user_specified: bool) -> Self {
        FieldPair {
            item,
            user_specified,
        }
    }
}

#[derive(Debug)]
pub struct ConfigInitializationData {
    pub(crate) chain: FieldPair<Chain>,
    pub(crate) real_user: FieldPair<RealUser>,
    pub(crate) data_directory: FieldPair<PathBuf>,
    pub(crate) config_file: FieldPair<PathBuf>,
}

fn get_chain_from_mc(multi_config: &MultiConfig) -> FieldPair<Chain> {
    let chain = value_m!(multi_config, "chain", String);
    match chain {
        Some(chain) => FieldPair::new(Chain::from(&*chain), true),
        None => FieldPair::new(DEFAULT_CHAIN, false),
    }
}

fn get_real_user_from_mc(
    multi_config: &MultiConfig,
    dirs_wrapper: &dyn DirsWrapper,
) -> FieldPair<RealUser> {
    let real_user = value_m!(multi_config, "real-user", RealUser);
    match real_user {
        Some(user) => FieldPair::new(user, true),
        None => {
            #[cfg(target_os = "windows")]
            {
                FieldPair::new(
                    RealUser::new(Some(999999), Some(999999), None).populate(dirs_wrapper),
                    false,
                )
            }
            #[cfg(not(target_os = "windows"))]
            {
                FieldPair::new(
                    RealUser::new(None, None, None).populate(dirs_wrapper),
                    false,
                )
            }
        }
    }
}

fn get_data_directory_from_mc(
    multi_config: &MultiConfig,
    dirs_wrapper: &dyn DirsWrapper,
    real_user: &RealUser,
    chain: &Chain,
) -> FieldPair<PathBuf> {
    let data_directory = value_m!(multi_config, "data-directory", PathBuf);
    match data_directory {
        Some(data_dir) => match data_dir.starts_with("~/") {
            true => {
                let home_dir_from_wrapper = dirs_wrapper
                    .home_dir()
                    .expect("expected users home dir")
                    .to_str()
                    .expect("expected home dir")
                    .to_string();
                let replaced_tilde_dir =
                    data_dir
                        .display()
                        .to_string()
                        .replacen('~', home_dir_from_wrapper.as_str(), 1);
                FieldPair::new(PathBuf::from(replaced_tilde_dir), true)
            }
            false => FieldPair::new(data_dir, true),
        },
        None => FieldPair::new(
            data_directory_from_context(dirs_wrapper, real_user, *chain),
            false,
        ),
    }
}

fn replace_tilde(config_path: PathBuf, dirs_wrapper: &dyn DirsWrapper) -> PathBuf {
    match config_path.starts_with("~") {
        true => PathBuf::from(
            config_path.display().to_string().replacen(
                '~',
                dirs_wrapper
                    .home_dir()
                    .expect("expected users home dir")
                    .to_str()
                    .expect("expected home dir"),
                1,
            ),
        ),
        false => config_path,
    }
}

fn replace_dots(config_path: PathBuf) -> PathBuf {
    match config_path.starts_with("./") || config_path.starts_with("../") {
        true => current_dir()
            .expect("expected current dir")
            .join(config_path),
        false => config_path,
    }
}

fn replace_relative_path(
    config_path: PathBuf,
    data_directory_def: bool,
    data_directory: &Path,
    panic: &mut bool,
) -> PathBuf {
    match config_path.is_relative() {
        true => match data_directory_def {
            true => data_directory.join(config_path),
            false => {
                *panic = true;
                config_path
            }
        },
        false => config_path,
    }
}

fn get_config_file_from_mc(
    multi_config: &MultiConfig,
    data_directory: &Path,
    data_directory_def: bool,
    dirs_wrapper: &dyn DirsWrapper,
) -> FieldPair<PathBuf> {
    let mut panic: bool = false;
    let config_file = value_m!(multi_config, "config-file", PathBuf);
    match config_file {
        Some(config_path) => {
            let config_path = replace_tilde(config_path, dirs_wrapper);
            let config_path = replace_dots(config_path);
            let config_path =
                replace_relative_path(config_path, data_directory_def, data_directory, &mut panic);
            if panic {
                panic!(
                    "If the config file is given with a naked relative path ({}), the data directory must be given to serve as the root for the config-file path.",
                    config_path.to_string_lossy()
                );
            }
            FieldPair::new(config_path, true)
        }
        None => {
            let path = data_directory.join(PathBuf::from("config.toml"));
            match path.is_file() {
                true => FieldPair::new(path, true),
                false => FieldPair::new(path, false),
            }
        }
    }
}

fn config_file_data_dir_real_user_chain_from_mc(
    dirs_wrapper: &dyn DirsWrapper,
    multi_config: MultiConfig,
) -> ConfigInitializationData {
    let mut initialization_data = ConfigInitializationData {
        chain: Default::default(),
        real_user: Default::default(),
        data_directory: Default::default(),
        config_file: Default::default(),
    };

    initialization_data.chain = get_chain_from_mc(&multi_config);
    initialization_data.real_user = get_real_user_from_mc(&multi_config, dirs_wrapper);
    initialization_data.data_directory = get_data_directory_from_mc(
        &multi_config,
        dirs_wrapper,
        &initialization_data.real_user.item,
        &initialization_data.chain.item,
    );
    initialization_data.config_file = get_config_file_from_mc(
        &multi_config,
        &initialization_data.data_directory.item,
        initialization_data.data_directory.user_specified,
        dirs_wrapper,
    );
    initialization_data
}

pub fn determine_user_specific_data(
    dirs_wrapper: &dyn DirsWrapper,
    app: &App,
    args: &[String],
) -> Result<ConfigInitializationData, ConfiguratorError> {
    let orientation_args: Box<dyn VirtualCommandLine> = merge(
        Box::new(EnvironmentVcl::new(app)),
        Box::new(CommandLineVcl::new(args.to_vec())),
    );
    /* We create multiconfig to retrieve chain, real-user, data-directory and config file, to establish ConfigVcl */
    let first_multi_config =
        make_new_multi_config(app, vec![orientation_args]).expect("expected MultiConfig");
    let initialization_data =
        config_file_data_dir_real_user_chain_from_mc(dirs_wrapper, first_multi_config);

    Ok(initialization_data)
}

pub fn initialize_database(
    data_directory: &Path,
    migrator_config: DbInitializationConfig,
    db_password_opt: &Option<String>,
) -> Box<dyn PersistentConfiguration> {
    let conn = DbInitializerReal::default()
        .initialize(data_directory, migrator_config)
        .unwrap_or_else(|e| db_connection_launch_panic(e, data_directory));
    let mut persistent_config = Box::new(PersistentConfigurationReal::from(conn));
    if let Some(password) = db_password_opt {
        if persistent_config.check_password(None).expect("Failed to check password") {
            persistent_config.change_password(None, password).expect("Failed to establish password")
        }
    }
    persistent_config
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

pub struct DirsWrapperReal {}

impl DirsWrapper for DirsWrapperReal {
    fn data_dir(&self) -> Option<PathBuf> {
        data_local_dir()
    }
    fn home_dir(&self) -> Option<PathBuf> {
        home_dir()
    }
    fn dup(&self) -> Box<dyn DirsWrapper> {
        Box::new(DirsWrapperReal::default())
    }
}

impl DirsWrapperReal {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DirsWrapperReal {
    fn default() -> Self {
        DirsWrapperReal::new()
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
        let chain_name = "polygon-amoy";

        let result =
            data_directory_from_context(&dirs_wrapper, &real_user, Chain::from(chain_name));

        assert_eq!(
            result,
            PathBuf::from(
                "/nonexistent_home/nonexistent_alice/.local/share/MASQ/polygon-amoy".to_string()
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
            .param(
                "--data-directory",
                &data_directory.to_string_lossy().to_string(),
            )
            .param("--config-file", "booga.toml");
        let args_vec: Vec<String> = args.into();
        let app = determine_config_file_path_app();

        let user_specific_data =
            determine_user_specific_data(&DirsWrapperReal::default(), &app, args_vec.as_slice())
                .unwrap();

        assert_eq!(
            &format!(
                "{}",
                user_specific_data
                    .config_file
                    .item
                    .parent()
                    .unwrap()
                    .display()
            ),
            &user_specific_data
                .data_directory
                .item
                .to_string_lossy()
                .to_string(),
        );
        assert_eq!(
            "booga.toml",
            user_specific_data.config_file.item.file_name().unwrap()
        );
        assert_eq!(user_specific_data.real_user.user_specified, false);
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
        let app = determine_config_file_path_app();

        let user_specific_data =
            determine_user_specific_data(&DirsWrapperReal::default(), &app, args_vec.as_slice())
                .unwrap();
        assert_eq!(
            format!(
                "{}",
                user_specific_data
                    .config_file
                    .item
                    .parent()
                    .unwrap()
                    .display()
            ),
            user_specific_data
                .data_directory
                .item
                .to_string_lossy()
                .to_string(),
        );
        assert_eq!(
            "booga.toml",
            user_specific_data.config_file.item.file_name().unwrap()
        );
        assert_eq!(user_specific_data.config_file.user_specified, true);
        assert_eq!(user_specific_data.real_user.user_specified, false); //all these assertions of 'real_user_specified' was incorrect, no idea how this tests could pass before
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", "/tmp/booga.toml");
        let args_vec: Vec<String> = args.into();

        let app = determine_config_file_path_app();
        let user_specific_data =
            determine_user_specific_data(&DirsWrapperReal::default(), &app, args_vec.as_slice())
                .unwrap();

        assert_eq!(
            "/tmp/booga.toml",
            &format!("{}", user_specific_data.config_file.item.display())
        );
        assert_eq!(user_specific_data.config_file.user_specified, true);
        assert_eq!(user_specific_data.real_user.user_specified, false);
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
            &DirsWrapperReal::default(),
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\tmp\booga.toml",
            &format!("{}", user_specific_data.config_file.item.display())
        );
        assert_eq!(user_specific_data.config_file.user_specified, true);
        assert_eq!(user_specific_data.real_user.user_specified, false);
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
            &DirsWrapperReal::default(),
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:\tmp\booga.toml",
            &format!("{}", user_specific_data.config_file.item.display())
        );
        assert_eq!(user_specific_data.real_user.user_specified, false);
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
            &DirsWrapperReal::default(),
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\\TMP\booga.toml",
            &format!("{}", user_specific_data.config_file.item.display())
        );
        assert_eq!(user_specific_data.real_user.user_specified, false);
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
            &DirsWrapperReal::default(),
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:tmp\booga.toml",
            &format!("{}", user_specific_data.config_file.item.display())
        );
        assert_eq!(user_specific_data.real_user.user_specified, false);
    }

    #[test]
    fn initialize_database_handles_preexisting_database_with_existing_password() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "initialize_database_handles_preexisting_database_with_existing_password",
        );
        {
            let conn = DbInitializerReal::default()
                .initialize(&data_directory, DbInitializationConfig::test_default())
                .unwrap();
            let mut persistent_config = Box::new(PersistentConfigurationReal::from(conn));
            persistent_config.change_password(None, "existing password").unwrap();
        }
        let db_password = Some("command-line password".to_string());

        let persistent_config = initialize_database(
            &data_directory,
            DbInitializationConfig::test_default(),
            &db_password,
        );

        assert_eq!(persistent_config.check_password(Some("existing password".to_string())), Ok(true));
    }

    #[test]
    fn initialize_database_handles_preexisting_database_with_existing_password_but_nothing_on_the_command_line() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator",
            "initialize_database_handles_preexisting_database_with_existing_password_but_nothing_on_the_command_line",
        );
        {
            let conn = DbInitializerReal::default()
                .initialize(&data_directory, DbInitializationConfig::test_default())
                .unwrap();
            let mut persistent_config = Box::new(PersistentConfigurationReal::from(conn));
            persistent_config.change_password(None, "existing password").unwrap();
        }
        let db_password = None;

        let persistent_config = initialize_database(
            &data_directory,
            DbInitializationConfig::test_default(),
            &db_password,
        );

        assert_eq!(persistent_config.check_password(Some("existing password".to_string())), Ok(true));
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
