// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod configurator;
pub mod node_configurator_initialization;
pub mod node_configurator_standard;
pub mod unprivileged_parse_args_configuration;

use std::env::{current_dir};
use crate::bootstrapper::RealUser;
use core::option::Option;
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::utils::db_connection_launch_panic;
use clap::{value_t, App};
use dirs::{data_local_dir, home_dir};
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::DEFAULT_CHAIN;
use masq_lib::multi_config::{merge, CommandLineVcl, EnvironmentVcl, MultiConfig, VclArg, VirtualCommandLine, ConfigFileVcl, ConfigFileVclError};
use masq_lib::shared_schema::{config_file_arg, data_directory_arg, ConfiguratorError, DATA_DIRECTORY_HELP, chain_arg, real_user_arg};
use masq_lib::utils::{add_masq_and_chain_directories, localhost};
use std::net::{SocketAddr, TcpListener};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use libc::option;


pub trait NodeConfigurator<T> {
    fn configure(&self, multi_config: &MultiConfig) -> Result<T, ConfiguratorError>;
}

fn config_file_data_dir_real_user_chain_from_enumerate(dirs_wrapper: &dyn DirsWrapper, configs: Vec<Box<dyn VclArg>>)
    -> (Option<PathBuf>, Option<PathBuf>, Option<RealUser>, Option<Chain>) {
    let configs = configs.as_slice();
    let chain = match argument_from_enumerate(configs, "--chain") {
        Some(chain) => Chain::from( chain),
        None => DEFAULT_CHAIN
    };
    let real_user = match argument_from_enumerate(configs, "--real-user") {
        Some(user) => {
            let real_user_split: Vec<&str> = user.split(":").collect();
            RealUser::new(
                Some(real_user_split[0].parse::<i32>().expect("expected user id")),
                Some(real_user_split[1].parse::<i32>().expect("expected user group")),
                Some(PathBuf::from(real_user_split[2]))
            )

        },
        None => RealUser::new(None, None, None).populate(dirs_wrapper)
    };
    let data_directory = match argument_from_enumerate(configs, "--data-directory") {
        Some(data_dir) => PathBuf::from(&data_dir),
        None => data_directory_from_context(dirs_wrapper, &real_user, chain)
    };
    let config_match = match argument_from_enumerate(configs, "--config-file") {
        Some(config_str) => {
            match PathBuf::from(config_str).is_relative() {
                true => current_dir().expect("expected curerrnt dir").join(PathBuf::from(config_str)),
                false => PathBuf::from(config_str)
            }
        }
        None => PathBuf::from(&data_directory).join(PathBuf::from("config.toml"))
    };
    (Some(config_match), Some(data_directory), Some(real_user), Some(chain))
}

fn argument_from_enumerate<'a>(configs: &'a [Box<dyn VclArg>], needle: &'a str) -> Option<&'a str> {
    match configs
        .iter()
        .find(|vcl_arg_box| vcl_arg_box.deref().name() == needle ) {
        Some(vcl_arg_box) => vcl_arg_box.deref().value_opt(),
        None => None
    }
}

#[derive(Debug)]
pub struct UserSpecificData {
    pub(crate) config_file: PathBuf,
    pub(crate) config_file_specified: bool,
    pub(crate) data_directory: Option<PathBuf>,
    pub(crate) data_directory_specified: bool,
    pub(crate) real_user: Option<RealUser>,
    pub(crate) real_user_specified: bool,
    // pub config_file_vcl: Box<ConfigFileVcl>,
}

pub fn determine_user_specific_data (
    dirs_wrapper: &dyn DirsWrapper,
    app: &App,
    args: &[String],
) -> Result<UserSpecificData, ConfiguratorError> {

    // let pre_orientation_args = match create_preorientation_args(args, &app, dirs_wrapper);
    let mut data_directory_specified: bool = false;
    let mut real_user_specified: bool = false;
    let mut config_file_specified: bool = false;
    let config_file_path: PathBuf;
    let orientation_schema = App::new("MASQNode")
        .arg(chain_arg())
        .arg(real_user_arg())
        .arg(data_directory_arg(DATA_DIRECTORY_HELP))
        .arg(config_file_arg());
    let orientation_args: Vec<Box<dyn VclArg>> = merge(
        Box::new(EnvironmentVcl::new(&orientation_schema)),
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
    let (config_file,data_directory,real_user, chain) =
        config_file_data_dir_real_user_chain_from_enumerate( dirs_wrapper, orientation_args);
    match config_file {
        Some(config_file_pth) => {
            config_file_specified = true;
            config_file_path = config_file_pth;
            // match ConfigFileVcl::new(&config_file_path, config_file_specified) {
            //     Ok(cfv) => Box::new(cfv),
            //     Err(e) => return Err(ConfiguratorError::required("config-file", &e.to_string())),
            // }
        }
        None => {
            config_file_specified = false;
            config_file_path = data_directory.clone().expect("expect data directory").join("config.toml");
            // match ConfigFileVcl::new(&config_file_path, config_file_specified) {
            //     Ok(cfv) => Box::new(cfv),
            //     Err(e) => e,
            // }
        }
    };
    //println!("determine_user_specific_data orientation_args {:#?}", &orientation_args);
    {// let config_file_vcl = match ConfigFileVcl::new(&config_file_path, config_file_specified) {
        //     Ok(cfv) => Box::new(cfv),
        //     Err(e) => return Err(ConfiguratorError::required("config-file", &e.to_string())),
        // };

        // let config_user_specified = !config_file.is_empty();
        // let data_directory_specified = !data_dir.is_empty();
        // let real_user_specified = !real_user.is_empty();
        // if real_user.is_empty() {
        //     real_user = RealUser::new(None, None, None).populate(dirs_wrapper).to_string();
        // }
        // let chain = match argument_from_enumerate(&orientation_vcl.args(), "--chain") {
        //     Some(chain) => {
        //         Chain::from(chain.as_str())
        //     },
        //     None => DEFAULT_CHAIN
        // };
        // let real_user_split: Vec<&str> = real_user.split(":").collect();
        // let real_user_obj = RealUser::new(
        //     Some(real_user_split[0].parse::<i32>().expect("expected user id")),
        //     Some(real_user_split[1].parse::<i32>().expect("expected user group")),
        //     Some(PathBuf::from(real_user_split[2])));
        // let data_directory = match data_dir.is_empty() {
        //     false => PathBuf::from(data_dir),
        //     true => data_directory_from_context(dirs_wrapper, &real_user_obj, chain),
        // };
        // let final_orientation_args;
        // if !config_user_specified {
        //     config_file = data_directory.join("config.toml").to_string_lossy().to_string();
        //     final_orientation_args = merge(
        //         Box::new(orientation_vcl),
        //         Box::new(CommandLineVcl::new(vec!["".to_string(), "--config-file".to_string(), config_file.clone()]))
        //     );
        // } else {
        //     final_orientation_args = Box::new(orientation_vcl);
        // }
        // let final_orientation_args = Box::new(orientation_vcl);
        }
    Ok( UserSpecificData {
        config_file: config_file_path,
        config_file_specified,
        data_directory,
        data_directory_specified,
        real_user,
        real_user_specified,
        // config_file_vcl
    }
    )
}

struct CombinedVcl {
    content: Vec<String>
}

impl CombinedVcl {
    fn len(&self) -> u32 {
        *&self.content.as_slice().iter().count() as u32
    }
}

struct UserDefinedData {
    real_user: String,
    data_directory: String,
    config_file: String,
    real_user_type: RealUser,
    data_directory_path: PathBuf,
    config_file_path: PathBuf
}

// fn create_preorientation_args(cmd_args: &[String], app: &App, dirs_wrapper: &dyn DirsWrapper,) -> Result<Box<dyn VirtualCommandLine>, ConfigFileVclError> {
//     let env_args = Box::new(EnvironmentVcl::new(&app)).args();
//     let cmd_args = cmd_args.to_vec();
//     let (env_config_file, env_data_dir, env_real_user) = config_file_data_dir_real_user_chain_from_enumerate(Box::new(dirs_wrapper), &env_args);
//     let (cmd_config_file, cmd_data_dir, cmd_real_user) = config_file_data_dir_real_user_chain_from_enumerate(Box::new(dirs_wrapper), &cmd_args);
//     let mut combined_vcl: CombinedVcl = CombinedVcl { content: vec![] };
//     let combine_vcl = | name: String, vcl: &mut CombinedVcl, cmd_str: &String, env_str: &String | {
//         if !cmd_str.is_empty() {
//             vcl.content.push(name);
//             vcl.content.push(cmd_str.to_string());
//         }
//         else if !env_str.is_empty() {
//             vcl.content.push(name);
//             vcl.content.push(env_str.to_string());
//         }
//         else {
//             vcl.content.push(name);
//             vcl.content.push("".to_string());
//         }
//     };
//     combine_vcl("--data-directory".to_string(), &mut combined_vcl, &cmd_data_dir, &env_data_dir);
//     combine_vcl("--config-file".to_string(), &mut combined_vcl, &cmd_config_file, &env_config_file);
//     combine_vcl("--real-user".to_string(), &mut combined_vcl, &cmd_real_user, &env_real_user);
//
//     // In case we define config file in ENV and we can find real-user in that file, therefore we need
//     // to specify also data-directory in Environment or Command line, to be Node able figure out the
//     // config file location, when config file is specified without absolute path or current directory eg.: "./" or "../"
//
//     let mut user_defined = UserDefinedData {
//         real_user: Default::default(),
//         data_directory: Default::default(),
//         config_file: Default::default(),
//         real_user_type: RealUser::new(None, None, None).populate(dirs_wrapper),
//         data_directory_path: data_directory_from_context(dirs_wrapper, &RealUser::new(None, None, None).populate(dirs_wrapper), DEFAULT_CHAIN),
//         config_file_path: Default::default(),
//     };
//
//     let preargs: Box<dyn VirtualCommandLine>;
//
//     match combined_vcl.len() > 0 {
//         true => {
//             (user_defined.config_file, user_defined.data_directory, user_defined.real_user) = config_file_data_dir_real_user_from_enumerate(&combined_vcl.content);
//             match user_defined.config_file.is_empty() {
//                 true => {
//                     user_defined.config_file = "config.toml".to_string();
//                     check_status_of_data_directory(&mut user_defined);
//                     user_defined.config_file_path = user_defined.data_directory_path.join(user_defined.config_file_path);
//                 }
//                 false => {
//                     match check_status_of_config_file(&user_defined) {
//                         Ok(_) => {}
//                         Err(path) => {
//                             return Err(ConfigFileVclError::InvalidConfig(
//                                 path,
//                                 "Config file defined in Environment with relative path needs data-directory to be defined too".to_string()
//                             ))
//                         }
//                     }
//                 }
//             }
//             set_user_defined_config_file_and_path(&mut user_defined);
//             let user_specified = !user_defined.config_file.is_empty();
//             let config_file_vcl = match ConfigFileVcl::new(&user_defined.config_file_path, user_specified) {
//                 Ok(cfv) => Box::new(cfv),
//                 Err(e) => return Err(e),
//             };
//             preargs = merge(
//                 config_file_vcl,
//                 Box::new(EnvironmentVcl::new(app)),
//             );
//             println!("preargs in first match config-file empty: {:#?}", preargs);
//         }
//         false => {
//             user_defined.config_file_path = PathBuf::from(user_defined.data_directory).join(user_defined.config_file);
//             let config_file_vcl = match ConfigFileVcl::new(&user_defined.config_file_path, false) {
//                 Ok(cfv) => Box::new(cfv),
//                 Err(e) => return Err(e),
//             };
//             preargs = merge(
//                 config_file_vcl,
//                 Box::new(EnvironmentVcl::new(app)),
//             );
//         }
//     }
//
//     let args = merge(
//         preargs,
//         Box::new(CommandLineVcl::new(
//             vec!["".to_string(),
//                  "--config-file".to_string(),
//                  user_defined.config_file_path.to_string_lossy().to_string()]
//         ))
//     );
//     Ok(args)
// }

fn set_user_defined_config_file_and_path(user_defined: &mut UserDefinedData) {
    if user_defined.config_file.starts_with("./") {
        let pwd = current_dir().expect("expected current directory from system call");
        user_defined.config_file = user_defined.config_file.replacen(".", pwd.to_string_lossy().to_string().as_str(), 1);
    }
    user_defined.config_file_path = PathBuf::from(&user_defined.config_file.to_string());
    if user_defined.config_file_path.is_relative() && !user_defined.data_directory.is_empty() {
        user_defined.config_file_path = PathBuf::from(user_defined.data_directory.clone().to_string()).join(&user_defined.config_file_path);
    }
}

fn check_status_of_data_directory(user_defined: &mut UserDefinedData) {
    match user_defined.data_directory.is_empty() {
        true => {},
        false => {
            user_defined.data_directory_path = PathBuf::from(&user_defined.data_directory);
        }
    }
}

fn check_status_of_config_file(user_defined: &UserDefinedData) -> Result<(), PathBuf> {
    return if (!user_defined.config_file.starts_with("/") && !user_defined.config_file.starts_with("./") && !user_defined.config_file.starts_with("../"))
        && user_defined.data_directory.is_empty() {
        Err(PathBuf::from(&user_defined.config_file))
    } else { Ok(()) }
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
            &format!("{}", user_specific_data.config_file.parent().unwrap().display()),
            &user_specific_data.data_directory.unwrap().to_string_lossy().to_string(),
        );
        assert_eq!("booga.toml", user_specific_data.config_file.file_name().unwrap());
        assert_eq!(true, user_specific_data.real_user_specified);
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
            format!("{}", user_specific_data.config_file.parent().unwrap().display()),
            user_specific_data.data_directory.unwrap().to_string_lossy().to_string(),
        );
        assert_eq!("booga.toml", user_specific_data.config_file.file_name().unwrap());
        assert_eq!(true, user_specific_data.real_user_specified);
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
        assert_eq!(true, user_specific_data.real_user_specified);
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
        assert_eq!(true, user_specific_data.real_user_specified);
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
        assert_eq!(true, user_specific_data.real_user_specified);
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
        assert_eq!(true, user_specific_data.real_user_specified);
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
        assert_eq!(true, user_specific_data.real_user_specified);
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
