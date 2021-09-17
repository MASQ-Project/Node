// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod configurator;
pub mod node_configurator_initialization;
pub mod node_configurator_standard;

use crate::bootstrapper::RealUser;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::utils::make_new_multi_config;
use clap::{value_t, App};
use dirs::{data_local_dir, home_dir};
use masq_lib::command::StdStreams;
use masq_lib::constants::DEFAULT_CHAIN_NAME;
use masq_lib::multi_config::{merge, CommandLineVcl, EnvironmentVcl, MultiConfig, VclArg};
use masq_lib::shared_schema::{
    chain_arg, config_file_arg, data_directory_arg, real_user_arg, ConfiguratorError,
};
use masq_lib::utils::{localhost, ExpectValue, WrapResult};
use std::fmt::Debug;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};

pub trait NodeConfigurator<T> {
    fn configure(
        &self,
        multi_config: &MultiConfig,
        streams: Option<&mut StdStreams<'_>>,
    ) -> Result<T, ConfiguratorError>;
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

pub mod common_validators {
    use masq_lib::constants::LOWEST_USABLE_INSECURE_PORT;
    use regex::Regex;
    use tiny_hderive::bip44::DerivationPath;

    pub fn validate_earning_wallet(value: String) -> Result<(), String> {
        validate_ethereum_address(value.clone()).or_else(|_| validate_derivation_path(value))
    }

    pub fn validate_ethereum_address(address: String) -> Result<(), String> {
        if Regex::new("^0x[0-9a-fA-F]{40}$")
            .expect("Failed to compile regular expression")
            .is_match(&address)
        {
            Ok(())
        } else {
            Err(address)
        }
    }

    pub fn validate_derivation_path(path: String) -> Result<(), String> {
        let possible_path = path.parse::<DerivationPath>();

        match possible_path {
            Ok(derivation_path) => {
                validate_derivation_path_is_sufficiently_hardened(derivation_path, path)
            }
            Err(e) => Err(format!("{} is not valid: {:?}", path, e)),
        }
    }

    pub fn validate_derivation_path_is_sufficiently_hardened(
        derivation_path: DerivationPath,
        path: String,
    ) -> Result<(), String> {
        if derivation_path
            .iter()
            .filter(|child_nbr| child_nbr.is_hardened())
            .count()
            > 2
        {
            Ok(())
        } else {
            Err(format!("{} may be too weak", path))
        }
    }

    pub fn validate_real_user(triple: String) -> Result<(), String> {
        if Regex::new("^[0-9]*:[0-9]*:.*$")
            .expect("Failed to compile regular expression")
            .is_match(&triple)
        {
            Ok(())
        } else {
            Err(triple)
        }
    }

    pub fn validate_ui_port(port: String) -> Result<(), String> {
        match str::parse::<u16>(&port) {
            Ok(port_number) if port_number < LOWEST_USABLE_INSECURE_PORT => Err(port),
            Ok(_) => Ok(()),
            Err(_) => Err(port),
        }
    }
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

#[derive(Debug, PartialEq)]
pub enum Either<L: Debug + PartialEq, R: Debug + PartialEq> {
    Left(L),
    Right(R),
}

#[derive(PartialEq, Debug)]
pub struct DerivationPathWalletInfo {
    pub mnemonic_seed: PlainData,
    pub db_password: String,
    pub consuming_derivation_path_opt: Option<String>,
}

#[derive(PartialEq, Debug)]
pub struct WalletCreationConfig {
    pub earning_wallet_address_opt: Option<String>,
    pub derivation_path_info_opt: Option<DerivationPathWalletInfo>,
    pub real_user: RealUser,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::app_node;
    use crate::masq_lib::utils::{
        DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
    };
    use crate::sub_lib::utils::make_new_test_multi_config;
    use crate::test_utils::ArgsBuilder;
    use masq_lib::constants::DEFAULT_CHAIN_NAME;
    use masq_lib::utils::find_free_port;
    use std::net::{SocketAddr, TcpListener};
    use tiny_hderive::bip44::DerivationPath;

    #[test]
    fn validate_ethereum_address_requires_an_address_that_is_42_characters_long() {
        assert_eq!(
            Err(String::from("my-favorite-wallet.com")),
            common_validators::validate_ethereum_address(String::from("my-favorite-wallet.com")),
        );
    }

    #[test]
    fn validate_ethereum_address_must_start_with_0x() {
        assert_eq!(
            Err(String::from("x0my-favorite-wallet.com222222222222222222")),
            common_validators::validate_ethereum_address(String::from(
                "x0my-favorite-wallet.com222222222222222222"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_must_contain_only_hex_characters() {
        assert_eq!(
            Err(String::from("0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q")),
            common_validators::validate_ethereum_address(String::from(
                "0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_when_happy() {
        assert_eq!(
            Ok(()),
            common_validators::validate_ethereum_address(String::from(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"
            ))
        );
    }

    #[test]
    fn validate_earning_wallet_works_with_address() {
        assert!(common_validators::validate_earning_wallet(String::from(
            "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"
        ))
        .is_ok());
    }

    #[test]
    fn validate_earning_wallet_works_with_derivation_path() {
        assert!(common_validators::validate_earning_wallet(
            DEFAULT_EARNING_DERIVATION_PATH.to_string()
        )
        .is_ok());
    }

    #[test]
    fn validate_derivation_path_happy() {
        assert_eq!(
            Ok(()),
            common_validators::validate_derivation_path(
                DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
            )
        );
    }

    #[test]
    fn validate_derivation_path_sad_eth_address() {
        assert_eq!(
            Err(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF is not valid: InvalidDerivationPath"
                    .to_string()
            ),
            common_validators::validate_derivation_path(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF".to_string()
            )
        );
    }

    #[test]
    fn validate_derivation_path_sad_malformed_with_backslashes() {
        assert_eq!(
            Err(r"m\44'\60'\0'\0\0 is not valid: InvalidDerivationPath".to_string()),
            common_validators::validate_derivation_path(r"m\44'\60'\0'\0\0".to_string())
        );
    }

    #[test]
    fn validate_derivation_path_sad_malformed_missing_m() {
        assert_eq!(
            Err("/44'/60'/0'/0/0 is not valid: InvalidDerivationPath".to_string()),
            common_validators::validate_derivation_path("/44'/60'/0'/0/0".to_string())
        );
    }

    #[test]
    fn validate_derivation_path_sad_insufficiently_hardened() {
        assert_eq!(
            common_validators::validate_derivation_path("m/44/60/0/0/0".to_string()),
            Err("m/44/60/0/0/0 may be too weak".to_string()),
        );
    }

    #[test]
    fn validate_derivation_path_is_sufficiently_hardened_happy() {
        assert!(
            common_validators::validate_derivation_path_is_sufficiently_hardened(
                DEFAULT_CONSUMING_DERIVATION_PATH
                    .parse::<DerivationPath>()
                    .unwrap(),
                DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_derivation_path_is_sufficiently_hardened_sad() {
        assert_eq!(
            Err("m/44'/60'/0/0/0 may be too weak".to_string()),
            common_validators::validate_derivation_path_is_sufficiently_hardened(
                "m/44'/60'/0/0/0".parse::<DerivationPath>().unwrap(),
                "m/44'/60'/0/0/0".to_string(),
            )
        );
    }

    #[test]
    fn validate_derivation_path_is_sufficiently_hardened_very_sad() {
        assert_eq!(
            Err("m/44/60/0/0/0 may be too weak".to_string()),
            common_validators::validate_derivation_path_is_sufficiently_hardened(
                "m/44/60/0/0/0".parse::<DerivationPath>().unwrap(),
                "m/44/60/0/0/0".to_string(),
            )
        );
    }

    #[test]
    fn validate_real_user_accepts_all_fields() {
        let result = common_validators::validate_real_user(String::from("999:999:/home/booga"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_real_user_accepts_no_fields() {
        let result = common_validators::validate_real_user(String::from("::"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn validate_real_user_rejects_non_numeric_uid() {
        let result = common_validators::validate_real_user(String::from("abc:999:/home/booga"));

        assert_eq!(Err(String::from("abc:999:/home/booga")), result);
    }

    #[test]
    fn validate_real_user_rejects_non_numeric_gid() {
        let result = common_validators::validate_real_user(String::from("999:abc:/home/booga"));

        assert_eq!(Err(String::from("999:abc:/home/booga")), result);
    }

    #[test]
    fn validate_real_user_rejects_too_few_colons() {
        let result = common_validators::validate_real_user(String::from(":"));

        assert_eq!(Err(String::from(":")), result);
    }

    #[test]
    fn validate_real_user_accepts_too_many_colons() {
        let result = common_validators::validate_real_user(String::from(":::"));

        assert_eq!(Ok(()), result);
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
