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
use clap::Command;
use dirs::{data_local_dir, home_dir};
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::DEFAULT_CHAIN;
use masq_lib::multi_config::{merge, CommandLineVcl, EnvironmentVcl, MultiConfig, VclArg};
use masq_lib::shared_schema::{chain_arg, config_file_arg, data_directory_arg, real_user_arg, ConfigFile, ConfiguratorError, DataDirectory, DATA_DIRECTORY_HELP};
use masq_lib::utils::{add_masq_and_chain_directories, localhost};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use masq_lib::shared_schema::RealUser as ClapRealUser;

pub trait NodeConfigurator<T> {
    fn configure(&self, multi_config: &MultiConfig) -> Result<T, ConfiguratorError>;
}

pub fn determine_fundamentals(
    dirs_wrapper: &dyn DirsWrapper,
    app: &Command,
    args: &[String],
) -> Result<(PathBuf, bool, PathBuf, RealUser), ConfiguratorError> {
    let orientation_schema = Command::new("MASQNode")
        .arg(chain_arg())
        .arg(real_user_arg())
        .arg(data_directory_arg(DATA_DIRECTORY_HELP.to_string()))
        .arg(config_file_arg());
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
    let orientation_vcl = CommandLineVcl::from(orientation_args);
    let multi_config = make_new_multi_config(&orientation_schema, vec![Box::new(orientation_vcl)])?;
    let config_file_path = value_m!(multi_config, "config-file", ConfigFile)
        .expect("config-file parameter is not properly defaulted by clap").path;
    let user_specified = multi_config.is_present("config-file");
    let (real_user, data_directory_path, chain) =
        real_user_data_directory_path_and_chain(dirs_wrapper, &multi_config);
    let data_directory = match data_directory_path {
        Some(data_dir) => data_dir,
        None => data_directory_from_context(dirs_wrapper, &real_user, chain),
    };
    let config_file_path = if config_file_path.is_relative() {
        data_directory.join(config_file_path)
    } else {
        config_file_path
    };

    Ok((config_file_path, user_specified, data_directory, real_user))
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
    match value_m!(multi_config, "real-user", ClapRealUser) {
        None => RealUser::new(None, None, None).populate(dirs_wrapper),
        Some(clap_real_user) => {
            let real_user = RealUser::from(clap_real_user);
            real_user.populate(dirs_wrapper)
        },
    }
}

pub fn real_user_data_directory_path_and_chain(
    dirs_wrapper: &dyn DirsWrapper,
    multi_config: &MultiConfig,
) -> (RealUser, Option<PathBuf>, Chain) {
    let real_user = real_user_from_multi_config_or_populate(multi_config, dirs_wrapper);
    let chain = value_m!(multi_config, "chain", Chain)
        .unwrap_or_else(|| DEFAULT_CHAIN);
    let data_directory_path = value_m!(multi_config, "data-directory", DataDirectory)
        .map(|data_dir| data_dir.path);
    (
        real_user,
        data_directory_path,
        chain,
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
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::find_free_port;
    use std::net::{SocketAddr, TcpListener};

    fn determine_config_file_path_app() -> Command {
        Command::new("test")
            .arg(data_directory_arg(DATA_DIRECTORY_HELP.to_string()))
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

        let result = data_directory_from_context(&dirs_wrapper, &real_user, Chain::PolyMumbai);

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

        let (config_file_path, user_specified, _data_dir, _real_user) = determine_fundamentals(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();
        assert_eq!(
            &format!("{}", config_file_path.parent().unwrap().display()),
            &data_directory.to_string_lossy().to_string(),
        );
        assert_eq!("booga.toml", config_file_path.file_name().unwrap());
        assert_eq!(true, user_specified);
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

        let (config_file_path, user_specified, _data_dir, _real_user) = determine_fundamentals(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();
        assert_eq!(
            format!("{}", config_file_path.parent().unwrap().display()),
            data_directory.to_string_lossy().to_string(),
        );
        assert_eq!("booga.toml", config_file_path.file_name().unwrap());
        assert_eq!(true, user_specified);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", "/tmp/booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified, _data_dir, _real_user) = determine_fundamentals(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            "/tmp/booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_separator_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"\tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified, _data_dir, _real_user) = determine_fundamentals(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_drive_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"c:\tmp\booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified, _data_dir, _real_user) = determine_fundamentals(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:\tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn determine_config_file_path_ignores_data_dir_if_config_file_has_network_root() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--data-directory", "data-dir")
            .param("--config-file", r"\\TMP\booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified, _data_dir, _real_user) = determine_fundamentals(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"\\TMP\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
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

        let (config_file_path, user_specified, _data_dir, _real_user) = determine_fundamentals(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            r"c:tmp\booga.toml",
            &format!("{}", config_file_path.display())
        );
        assert_eq!(true, user_specified);
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
