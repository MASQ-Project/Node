// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod configurator;
pub mod node_configurator_initialization;
pub mod node_configurator_standard;

use crate::bootstrapper::RealUser;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::utils::make_new_multi_config;
use clap::{value_t, App};
use dirs::{data_local_dir, home_dir};
use masq_lib::constants::DEFAULT_CHAIN_NAME;
use masq_lib::multi_config::{merge, CommandLineVcl, EnvironmentVcl, MultiConfig, VclArg};
use masq_lib::shared_schema::{
    chain_arg, config_file_arg, data_directory_arg, real_user_arg, ConfiguratorError,
};
use masq_lib::utils::{localhost, ExpectValue, WrapResult};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

pub trait NodeConfigurator<T> {
    fn configure(&self, multi_config: &MultiConfig) -> Result<T, ConfiguratorError>;
}

pub fn determine_config_file_path(
    dirs_wrapper: &dyn DirsWrapper,
    app: &App,
    args: &[String],
) -> Result<(PathBuf, bool), ConfiguratorError> {
    let orientation_schema = App::new("MASQNode")
        .arg(chain_arg())
        .arg(real_user_arg())
        .arg(data_directory_arg())
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
    let config_file_path = value_m!(multi_config, "config-file", PathBuf).expect_v("config-file");
    let user_specified = multi_config.occurrences_of("config-file") > 0;
    let (real_user, data_directory_opt, chain_name) =
        real_user_data_directory_opt_and_chain_name(dirs_wrapper, &multi_config);
    let directory =
        data_directory_from_context(dirs_wrapper, &real_user, &data_directory_opt, &chain_name);
    (directory.join(config_file_path), user_specified).wrap_to_ok()
}

pub fn initialize_database(
    data_directory: &Path,
    chain_id: u8,
) -> Box<dyn PersistentConfiguration> {
    let conn = DbInitializerReal::default()
        .initialize(data_directory, chain_id, true)
        .unwrap_or_else(|e| {
            panic!(
                "Can't initialize database at {:?}: {:?}",
                data_directory.join(DATABASE_FILE),
                e
            )
        });
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

pub fn real_user_data_directory_opt_and_chain_name(
    dirs_wrapper: &dyn DirsWrapper,
    multi_config: &MultiConfig,
) -> (RealUser, Option<PathBuf>, String) {
    let real_user = real_user_from_multi_config_or_populate(multi_config, dirs_wrapper);
    let chain_name =
        value_m!(multi_config, "chain", String).unwrap_or_else(|| DEFAULT_CHAIN_NAME.to_string());
    let data_directory_opt = value_m!(multi_config, "data-directory", PathBuf);
    (real_user, data_directory_opt, chain_name)
}

pub fn data_directory_from_context(
    dirs_wrapper: &dyn DirsWrapper,
    real_user: &RealUser,
    data_directory_opt: &Option<PathBuf>,
    chain_name: &str,
) -> PathBuf {
    match data_directory_opt {
        Some(data_directory) => data_directory.clone(),
        None => {
            let right_home_dir = real_user
                .home_dir_opt
                .as_ref()
                .expect("No real-user home directory; specify --real-user")
                .to_string_lossy()
                .to_string();
            let wrong_home_dir = dirs_wrapper
                .home_dir()
                .expect("No privileged home directory; specify --data-directory")
                .to_string_lossy()
                .to_string();
            let wrong_local_data_dir = dirs_wrapper
                .data_dir()
                .expect("No privileged local data directory; specify --data-directory")
                .to_string_lossy()
                .to_string();
            let right_local_data_dir =
                wrong_local_data_dir.replace(&wrong_home_dir, &right_home_dir);
            PathBuf::from(right_local_data_dir)
                .join("MASQ")
                .join(chain_name)
        }
    }
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
    use crate::apps::app_node;
    use crate::sub_lib::utils::make_new_test_multi_config;
    use crate::test_utils::ArgsBuilder;
    use masq_lib::constants::DEFAULT_CHAIN_NAME;
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::utils::find_free_port;
    use std::net::{SocketAddr, TcpListener};

    fn determine_config_file_path_app() -> App<'static, 'static> {
        App::new("test")
            .arg(data_directory_arg())
            .arg(config_file_arg())
    }

    #[test]
    fn real_user_data_directory_and_chain_id_picks_correct_directory_for_default_chain() {
        let args = ArgsBuilder::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = make_new_test_multi_config(&app_node(), vec![vcl]).unwrap();

        let (real_user, data_directory_opt, chain_name) =
            real_user_data_directory_opt_and_chain_name(&DirsWrapperReal {}, &multi_config);
        let directory = data_directory_from_context(
            &DirsWrapperReal {},
            &real_user,
            &data_directory_opt,
            &chain_name,
        );

        let expected_root = DirsWrapperReal {}.data_dir().unwrap();
        let expected_directory = expected_root.join("MASQ").join(DEFAULT_CHAIN_NAME);
        assert_eq!(directory, expected_directory);
        assert_eq!(&chain_name, DEFAULT_CHAIN_NAME);
    }

    #[test]
    fn determine_config_file_path_finds_path_in_args() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new()
            .param("--clandestine-port", "2345")
            .param("--data-directory", "data-dir")
            .param("--config-file", "booga.toml");
        let args_vec: Vec<String> = args.into();

        let (config_file_path, user_specified) = determine_config_file_path(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            &format!("{}", config_file_path.parent().unwrap().display()),
            "data-dir",
        );
        assert_eq!("booga.toml", config_file_path.file_name().unwrap());
        assert_eq!(true, user_specified);
    }

    #[test]
    fn determine_config_file_path_finds_path_in_environment() {
        let _guard = EnvironmentGuard::new();
        let args = ArgsBuilder::new();
        let args_vec: Vec<String> = args.into();
        std::env::set_var("MASQ_DATA_DIRECTORY", "data_dir");
        std::env::set_var("MASQ_CONFIG_FILE", "booga.toml");

        let (config_file_path, user_specified) = determine_config_file_path(
            &DirsWrapperReal {},
            &determine_config_file_path_app(),
            args_vec.as_slice(),
        )
        .unwrap();

        assert_eq!(
            "data_dir",
            &format!("{}", config_file_path.parent().unwrap().display())
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

        let (config_file_path, user_specified) = determine_config_file_path(
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

        let (config_file_path, user_specified) = determine_config_file_path(
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

        let (config_file_path, user_specified) = determine_config_file_path(
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

        let (config_file_path, user_specified) = determine_config_file_path(
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

        let (config_file_path, user_specified) = determine_config_file_path(
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
