// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::bip39::Bip39;
use crate::multi_config::MultiConfig;
use crate::node_configurator::{
    app_head, chain_arg, common_validators, consuming_wallet_arg, create_wallet,
    data_directory_arg, earning_wallet_arg, flushed_write, language_arg, mnemonic_passphrase_arg,
    prepare_initialization_mode, real_user_arg, request_password_with_confirmation,
    request_password_with_retry, wallet_password_arg, Either, NodeConfigurator,
    WalletCreationConfig, WalletCreationConfigMaker, EARNING_WALLET_HELP, WALLET_PASSWORD_HELP,
};
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::wallet::Wallet;
use bip39::{Language, Mnemonic, MnemonicType};
use clap::{value_t, App, Arg};
use indoc::indoc;
use std::str::FromStr;
use unindent::unindent;

pub struct NodeConfiguratorGenerateWallet {
    app: App<'static, 'static>,
    mnemonic_factory: Box<dyn MnemonicFactory>,
}

impl NodeConfigurator<WalletCreationConfig> for NodeConfiguratorGenerateWallet {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> WalletCreationConfig {
        let (multi_config, persistent_config_box) = prepare_initialization_mode(&self.app, args);
        let persistent_config = persistent_config_box.as_ref();

        let config = self.parse_args(&multi_config, streams, persistent_config);

        create_wallet(&config, persistent_config);

        config
    }
}

pub trait MnemonicFactory {
    fn make(&self, mnemonic_type: MnemonicType, language: Language) -> Mnemonic;
}

struct MnemonicFactoryReal {}

impl MnemonicFactory for MnemonicFactoryReal {
    fn make(&self, mnemonic_type: MnemonicType, language: Language) -> Mnemonic {
        Bip39::mnemonic(mnemonic_type, language)
    }
}

const GENERATE_WALLET_HELP: &str =
    "Generate a new set of HD wallets with mnemonic recovery phrase from the standard \
     BIP39 predefined list of words. Not valid as an environment variable.";
const WORD_COUNT_HELP: &str =
    "The number of words in the mnemonic phrase. Ropsten defaults to 12 words. \
     Mainnet defaults to 24 words.";

const HELP_TEXT: &str = indoc!(
    r"ADDITIONAL HELP:
    If you already have a set of wallets you want SubstratumNode to use, try:

        SubstratumNode --help --recover-wallet

    If the Node is already configured with your wallets, and you want to start the Node so that it
    stays running:

        SubstratumNode --help"
);

impl WalletCreationConfigMaker for NodeConfiguratorGenerateWallet {
    fn make_mnemonic_passphrase(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
    ) -> String {
        match value_m!(multi_config, "mnemonic-passphrase", String) {
            Some(mp) => mp,
            None => match Self::request_mnemonic_passphrase(streams) {
                Some(mp) => mp,
                None => "".to_string(),
            },
        }
    }

    fn make_mnemonic_seed(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
        mnemonic_passphrase: &str,
        consuming_derivation_path: &str,
        earning_wallet_info: &Either<String, String>,
    ) -> PlainData {
        let language_str =
            value_m!(multi_config, "language", String).expect("--language is not defaulted");
        let language = Bip39::language_from_name(&language_str);
        let word_count =
            value_m!(multi_config, "word-count", usize).expect("--word-count is not defaulted");
        let mnemonic_type = MnemonicType::for_word_count(word_count)
            .expect("--word-count is not properly value-restricted");
        let mnemonic = self.mnemonic_factory.make(mnemonic_type, language);
        let seed = PlainData::new(Bip39::seed(&mnemonic, &mnemonic_passphrase).as_ref());
        Self::report_wallet_information(
            streams,
            &mnemonic,
            &seed,
            &consuming_derivation_path,
            &earning_wallet_info,
            multi_config.arg_matches().is_present("json"),
        );
        seed
    }
}

impl Default for NodeConfiguratorGenerateWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeConfiguratorGenerateWallet {
    pub fn new() -> Self {
        Self {
            app: app_head()
                .after_help(HELP_TEXT)
                .arg(
                    Arg::with_name("generate-wallet")
                        .long("generate-wallet")
                        .required(true)
                        .takes_value(false)
                        .requires_all(&["language", "word-count"])
                        .help(GENERATE_WALLET_HELP),
                )
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .takes_value(false)
                        .hidden(true),
                )
                .arg(chain_arg())
                .arg(consuming_wallet_arg())
                .arg(data_directory_arg())
                .arg(earning_wallet_arg(
                    EARNING_WALLET_HELP,
                    common_validators::validate_earning_wallet,
                ))
                .arg(language_arg())
                .arg(mnemonic_passphrase_arg())
                .arg(real_user_arg())
                .arg(wallet_password_arg(WALLET_PASSWORD_HELP))
                .arg(
                    Arg::with_name("word-count")
                        .long("word-count")
                        .required(true)
                        .value_name("WORD-COUNT")
                        .possible_values(&["12", "15", "18", "21", "24"])
                        .default_value("12")
                        .help(WORD_COUNT_HELP),
                ),
            mnemonic_factory: Box::new(MnemonicFactoryReal {}),
        }
    }

    fn parse_args(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
        persistent_config: &dyn PersistentConfiguration,
    ) -> WalletCreationConfig {
        if persistent_config.encrypted_mnemonic_seed().is_some() {
            panic!("Can't generate wallets: mnemonic seed has already been created")
        }
        self.make_wallet_creation_config(multi_config, streams)
    }

    fn request_mnemonic_passphrase(streams: &mut StdStreams) -> Option<String> {
        flushed_write (streams.stdout, "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique\n\
            (NOTE: This passphrase cannot be changed later and still produce the same addresses).\n\
            You will encrypt your wallet in a following step...\n",
        );
        match request_password_with_retry(
            "  Mnemonic passphrase (recommended): ",
            streams,
            |streams| {
                request_password_with_confirmation(
                    "  Confirm mnemonic passphrase: ",
                    "\nPassphrases do not match.",
                    streams,
                    |_| Ok(()),
                )
            },
        ) {
            Ok(mp) => {
                if mp.is_empty() {
                    flushed_write (
                        streams.stdout,
                        "\nWhile ill-advised, proceeding with no mnemonic passphrase.\nPress Enter to continue...",
                    );
                    let _ = streams.stdin.read(&mut [0u8]).is_ok();
                    None
                } else {
                    Some(mp)
                }
            }
            Err(e) => panic!("{:?}", e),
        }
    }

    fn report_wallet_information(
        streams: &mut StdStreams<'_>,
        mnemonic: &Mnemonic,
        seed: &PlainData,
        consuming_derivation_path: &str,
        earning_wallet_info: &Either<String, String>,
        json: bool,
    ) {
        let consuming_keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), &consuming_derivation_path)
            .unwrap_or_else(|_| {
                panic!(
                    "Couldn't make key pair from consuming derivation path '{}'",
                    consuming_derivation_path
                )
            });
        let consuming_wallet = Wallet::from(consuming_keypair);

        if json {
            let earning_wallet_object_body = match &earning_wallet_info {
                Either::Left(address) => {
                    let earning_wallet =
                        Wallet::from_str(address).expect("Address doesn't work anymore");
                    format!(r#""address": "{}""#, earning_wallet)
                }
                Either::Right(earning_derivation_path) => {
                    let earning_keypair =
                        Bip32ECKeyPair::from_raw(seed.as_ref(), &earning_derivation_path)
                            .unwrap_or_else(|_| {
                                panic!(
                                    "Couldn't make key pair from earning derivation path '{}'",
                                    earning_derivation_path
                                )
                            });
                    let earning_wallet = Wallet::from(earning_keypair.address());
                    format!(
                        r#""derivationPath": "{}",
                        "address": "{}""#,
                        earning_derivation_path, earning_wallet
                    )
                }
            };
            let result = unindent(&format!(
                r#"
                {{
                    "mnemonicPhrase": "{}",
                    "consumingWallet": {{
                        "derivationPath": "{}",
                        "address": "{}"
                    }},
                    "earningWallet": {{
                        {}
                    }}
                }}
                "#,
                mnemonic.phrase(),
                consuming_derivation_path,
                consuming_wallet,
                earning_wallet_object_body
            ));

            flushed_write(streams.stdout, &result);
        } else {
            flushed_write(
                streams.stdout,
                "\n\nRecord the following mnemonic recovery phrase in the sequence provided\n\
                 and keep it secret! You cannot recover your wallet without these words\n\
                 plus your mnemonic passphrase if you provided one.\n\n",
            );
            flushed_write(streams.stdout, mnemonic.phrase());
            flushed_write(streams.stdout, "\n\n");
            flushed_write(
                streams.stdout,
                &format!(
                    "Consuming Wallet ({}): {}\n",
                    consuming_derivation_path, consuming_wallet
                ),
            );
            match &earning_wallet_info {
                Either::Left(address) => {
                    let earning_wallet =
                        Wallet::from_str(address).expect("Address doesn't work anymore");
                    flushed_write(
                        streams.stdout,
                        &format!("  Earning Wallet: {}\n", earning_wallet),
                    );
                }
                Either::Right(earning_derivation_path) => {
                    let earning_keypair =
                        Bip32ECKeyPair::from_raw(seed.as_ref(), &earning_derivation_path)
                            .unwrap_or_else(|_| {
                                panic!(
                                    "Couldn't make key pair from earning derivation path '{}'",
                                    earning_derivation_path
                                )
                            });
                    let earning_wallet = Wallet::from(earning_keypair.address());
                    flushed_write(
                        streams.stdout,
                        &format!(
                            "  Earning Wallet ({}): {}\n",
                            earning_derivation_path, earning_wallet
                        ),
                    );
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::DEFAULT_CHAIN_NAME;
    use crate::bootstrapper::RealUser;
    use crate::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::database::db_initializer;
    use crate::database::db_initializer::DbInitializer;
    use crate::multi_config::{CommandLineVcl, VirtualCommandLine};
    use crate::node_configurator::DerivationPathWalletInfo;
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::wallet::DEFAULT_CONSUMING_DERIVATION_PATH;
    use crate::sub_lib::wallet::DEFAULT_EARNING_DERIVATION_PATH;
    use crate::test_utils::*;
    use bip39::Seed;
    use regex::Regex;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    struct MnemonicFactoryMock {
        make_parameters: Arc<Mutex<Vec<(MnemonicType, Language)>>>,
        make_results: RefCell<Vec<Mnemonic>>,
    }

    impl MnemonicFactory for MnemonicFactoryMock {
        fn make(&self, mnemonic_type: MnemonicType, language: Language) -> Mnemonic {
            let mut parameters = self.make_parameters.lock().unwrap();
            parameters.push((mnemonic_type, language));
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl MnemonicFactoryMock {
        pub fn new() -> MnemonicFactoryMock {
            MnemonicFactoryMock {
                make_parameters: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_parameters(
            mut self,
            parameters_arc: &Arc<Mutex<Vec<(MnemonicType, Language)>>>,
        ) -> MnemonicFactoryMock {
            self.make_parameters = parameters_arc.clone();
            self
        }

        pub fn make_result(self, result: Mnemonic) -> MnemonicFactoryMock {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn report_wallet_information_can_output_json_with_an_earning_derivation_path() {
        let mut streams = FakeStreamHolder::new();
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, "Mortimer");

        NodeConfiguratorGenerateWallet::report_wallet_information(
            &mut streams.streams(),
            &mnemonic,
            &PlainData::new(seed.as_bytes()),
            "m/44'/60'/0'/0/0",
            &Either::Right("m/44'/60'/0'/0/1".to_string()),
            true,
        );

        let result = streams.stdout.get_string();
        println!("{}", result);
        assert!(Regex::new("\"mnemonicPhrase\": \"(\\w+\\s){11}(\\w+)\"")
            .unwrap()
            .is_match(&result));
        assert!(Regex::new("\"consumingWallet\": \\{\\s+\"derivationPath\": \"m/(?:\\d+'/){3}(?:\\d+)(?:/\\d+)?\",\\s+\"address\": \"0x[\\da-fA-F]{40}\"\\s+\\}").unwrap().is_match(&result));
        assert!(Regex::new("\"earningWallet\": \\{\\s+\"derivationPath\": \"m/(?:\\d+'/){3}(?:\\d+)(?:/\\d+)?\",\\s+\"address\": \"0x[\\da-fA-F]{40}\"\\s+\\}").unwrap().is_match(&result));
    }

    #[test]
    fn report_wallet_information_can_output_json_without_an_earning_derivation_path() {
        let mut streams = FakeStreamHolder::new();
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, "Mortimer");

        NodeConfiguratorGenerateWallet::report_wallet_information(
            &mut streams.streams(),
            &mnemonic,
            &PlainData::new(seed.as_bytes()),
            "m/44'/60'/0'/0/0",
            &Either::Left("0x01234567890ABCDEFabcdef01234567890ABCDEF".to_string()),
            true,
        );

        let result = streams.stdout.get_string();
        println!("{}", result);
        assert!(Regex::new("\"mnemonicPhrase\": \"(\\w+\\s){11}(\\w+)\"")
            .unwrap()
            .is_match(&result));
        assert!(Regex::new("\"consumingWallet\": \\{\\s+\"derivationPath\": \"m/(?:\\d+'/){3}(?:\\d+)(?:/\\d+)?\",\\s+\"address\": \"0x[\\da-fA-F]{40}\"\\s+\\}").unwrap().is_match(&result));
        assert!(
            Regex::new("\"earningWallet\": \\{\\s+\"address\": \"0x[\\da-fA-F]{40}\"\\s+\\}")
                .unwrap()
                .is_match(&result)
        );
    }

    #[test]
    fn parse_args_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator_generate_wallet",
            "parse_args_creates_configurations",
        );

        let password = "secret-wallet-password";
        let args = ArgsBuilder::new()
            .opt("--generate-wallet")
            .param("--chain", DEFAULT_CHAIN_NAME)
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--wallet-password", password)
            .param("--consuming-wallet", "m/44'/60'/0'/77/78")
            .param("--earning-wallet", "m/44'/60'/0'/78/77")
            .param("--language", "español")
            .param("--word-count", "15")
            .param("--mnemonic-passphrase", "Mortimer")
            .param("--real-user", "123:456:/home/booga");
        let mut subject = NodeConfiguratorGenerateWallet::new();
        let make_parameters_arc = Arc::new(Mutex::new(vec![]));
        let expected_mnemonic = Mnemonic::new(MnemonicType::Words15, Language::Spanish);
        let mnemonic_factory = MnemonicFactoryMock::new()
            .make_parameters(&make_parameters_arc)
            .make_result(expected_mnemonic.clone());
        subject.mnemonic_factory = Box::new(mnemonic_factory);
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        let config = subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );
        let mut make_parameters = make_parameters_arc.lock().unwrap();
        assert_eq_debug(
            make_parameters.remove(0),
            (MnemonicType::Words15, Language::Spanish),
        );
        let seed = Seed::new(&expected_mnemonic, "Mortimer");
        let earning_wallet =
            Wallet::from(Bip32ECKeyPair::from_raw(seed.as_ref(), "m/44'/60'/0'/78/77").unwrap());
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: Some(earning_wallet.to_string()),
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(
                        Seed::new(&expected_mnemonic, "Mortimer").as_ref()
                    ),
                    wallet_password: password.to_string(),
                    consuming_derivation_path_opt: Some("m/44'/60'/0'/77/78".to_string()),
                }),
                real_user: RealUser::new(Some(123), Some(456), Some("/home/booga".into()))
            },
        );
    }

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new()
            .opt("--generate-wallet")
            .param("--chain", DEFAULT_CHAIN_NAME)
            .param("--wallet-password", "password123")
            .param("--mnemonic-passphrase", "Mortimer");
        let mut subject = NodeConfiguratorGenerateWallet::new();
        let make_parameters_arc = Arc::new(Mutex::new(vec![]));
        let expected_mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let mnemonic_factory = MnemonicFactoryMock::new()
            .make_parameters(&make_parameters_arc)
            .make_result(expected_mnemonic.clone());
        subject.mnemonic_factory = Box::new(mnemonic_factory);
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        let config = subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );

        let mut make_parameters = make_parameters_arc.lock().unwrap();
        assert_eq_debug(
            make_parameters.remove(0),
            (MnemonicType::Words12, Language::English),
        );
        let seed = Seed::new(&expected_mnemonic, "Mortimer");
        let earning_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(seed.as_ref(), DEFAULT_EARNING_DERIVATION_PATH).unwrap(),
        );
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: Some(earning_wallet.to_string()),
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(
                        Seed::new(&expected_mnemonic, "Mortimer").as_ref()
                    ),
                    wallet_password: "password123".to_string(),
                    consuming_derivation_path_opt: Some(
                        DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
                    ),
                }),
                real_user: RealUser::null(),
            },
        );
    }

    #[test]
    fn make_mnemonic_passphrase_allows_two_passphrase_mismatches() {
        let subject = NodeConfiguratorGenerateWallet::new();
        let mut stdout_writer = ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\neno\ntwo\nowt\nthree\nthree\n"[..]),
            stdout: &mut stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let args = ArgsBuilder::new().opt("--generate-wallet");
        let multi_config = MultiConfig::new(
            &subject.app,
            vec![Box::new(CommandLineVcl::new(args.into()))],
        );

        subject.make_mnemonic_passphrase(&multi_config, streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique\n\
                (NOTE: This passphrase cannot be changed later and still produce the same addresses).\n\
                You will encrypt your wallet in a following step...\n  Mnemonic passphrase (recommended):   Confirm mnemonic passphrase: \n\
                Passphrases do not match. Try again.\n  Mnemonic passphrase (recommended):   Confirm mnemonic passphrase: \n\
                Passphrases do not match. Try again.\n  Mnemonic passphrase (recommended):   Confirm mnemonic passphrase: ";
        assert_eq!(&captured_output, expected_output);
    }

    #[test]
    #[should_panic(expected = "RetriesExhausted")]
    fn make_mnemonic_passphrase_panics_after_three_passphrase_mismatches() {
        let subject = NodeConfiguratorGenerateWallet::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"one\neno\ntwo\nowt\nthree\neerht\n"[..]),
            stdout: &mut ByteArrayWriter::new(),
            stderr: &mut ByteArrayWriter::new(),
        };
        let args = ArgsBuilder::new().opt("--generate-wallet");
        let multi_config = MultiConfig::new(
            &subject.app,
            vec![Box::new(CommandLineVcl::new(args.into()))],
        );

        subject.make_mnemonic_passphrase(&multi_config, streams);
    }

    #[test]
    fn make_mnemonic_passphrase_allows_blank_passphrase_with_scolding() {
        let args = ArgsBuilder::new().opt("--generate-wallet");
        let mut subject = NodeConfiguratorGenerateWallet::new();
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let mnemonic_factory = MnemonicFactoryMock::new().make_result(mnemonic.clone());
        subject.mnemonic_factory = Box::new(mnemonic_factory);
        let stdout_writer = &mut ByteArrayWriter::new();
        let mut streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"\n\n\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.make_mnemonic_passphrase(&multi_config, &mut streams);

        let captured_output = stdout_writer.get_string();
        let expected_output = "\nPlease provide an extra mnemonic passphrase to ensure your wallet is unique\n\
        (NOTE: This passphrase cannot be changed later and still produce the same addresses).\n\
        You will encrypt your wallet in a following step...\n  Mnemonic passphrase (recommended):   Confirm mnemonic passphrase: \n\
        While ill-advised, proceeding with no mnemonic passphrase.\n\
        Press Enter to continue...";
        assert_eq!(&captured_output, expected_output);
    }

    #[test]
    #[should_panic(expected = "Can't generate wallets: mnemonic seed has already been created")]
    fn preexisting_mnemonic_seed_causes_collision_and_panics() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator_generate_wallet",
            "preexisting_mnemonic_seed_causes_collision_and_panics",
        );

        let conn = db_initializer::DbInitializerReal::new()
            .initialize(&data_directory, DEFAULT_CHAIN_ID)
            .unwrap();
        let config_dao = ConfigDaoReal::new(conn);
        config_dao.set_string("seed", "booga booga").unwrap();
        let args = ArgsBuilder::new()
            .opt("--generate-wallet")
            .param("--chain", DEFAULT_CHAIN_NAME)
            .param("--data-directory", data_directory.to_str().unwrap())
            .param("--wallet-password", "rick-rolled");
        let subject = NodeConfiguratorGenerateWallet::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &PersistentConfigurationReal::new(Box::new(config_dao)),
        );
    }
}
