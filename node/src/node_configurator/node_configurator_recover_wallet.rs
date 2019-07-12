// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::bip39::Bip39;
use crate::multi_config::MultiConfig;
use crate::node_configurator::{
    common_validators, config_file_arg, consuming_wallet_arg, create_wallet, data_directory_arg,
    earning_wallet_arg, flushed_write, initialize_database, language_arg, make_multi_config,
    mnemonic_passphrase_arg, request_existing_password, wallet_password_arg, Either,
    NodeConfigurator, WalletCreationConfig, WalletCreationConfigMaker, EARNING_WALLET_HELP,
    WALLET_PASSWORD_HELP,
};
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::main_tools::StdStreams;
use bip39::{Language, Mnemonic};
use clap::{
    crate_authors, crate_description, crate_version, value_t, values_t, App, AppSettings, Arg,
};
use indoc::indoc;

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;

pub struct NodeConfiguratorRecoverWallet {
    app: App<'static, 'static>,
}

impl NodeConfigurator<WalletCreationConfig> for NodeConfiguratorRecoverWallet {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> WalletCreationConfig {
        let multi_config = make_multi_config(&self.app, args);
        let persistent_config = initialize_database(&multi_config);

        let config = self.parse_args(&multi_config, streams, persistent_config.as_ref());

        create_wallet(&config, persistent_config.as_ref());

        config
    }
}

const RECOVER_WALLET_HELP: &str =
    "Import an existing set of HD wallets with mnemonic recovery phrase from the standard \
     BIP39 predefined list of words. Not valid as a configuration file item nor an \
     environment variable";
const MNEMONIC_HELP: &str =
    "An HD wallet mnemonic recovery phrase using predefined BIP39 word lists. Not valid as a \
     configuration file item nor an environment variable.";

const HELP_TEXT: &str = indoc!(
    r"ADDITIONAL HELP:
    If you already have a set of wallets, try:

        SubstratumNode --help --recover-wallet

    If the Node is already configured with your wallets, and you want to start the Node so that it
    stays running:

        SubstratumNode --help"
);

impl WalletCreationConfigMaker for NodeConfiguratorRecoverWallet {
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
        _consuming_derivation_path: &str,
        _earning_wallet_info: &Either<String, String>,
    ) -> PlainData {
        let language_str =
            value_m!(multi_config, "language", String).expect("--language is not defaulted");
        let language = Bip39::language_from_name(&language_str);
        let mnemonic = Self::get_mnemonic(language, multi_config, streams);
        PlainData::new(Bip39::seed(&mnemonic, &mnemonic_passphrase).as_ref())
    }
}

impl Default for NodeConfiguratorRecoverWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeConfiguratorRecoverWallet {
    pub fn new() -> NodeConfiguratorRecoverWallet {
        NodeConfiguratorRecoverWallet {
            app: App::new("SubstratumNode")
                .global_settings(if cfg!(test) {
                    &[AppSettings::ColorNever]
                } else {
                    &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
                })
                .version(crate_version!())
                .author(crate_authors!("\n"))
                .about(crate_description!())
                .after_help(HELP_TEXT)
                .arg(
                    Arg::with_name("recover-wallet")
                        .long("recover-wallet")
                        .aliases(&["recover-wallet", "recover_wallet"])
                        .required(true)
                        .takes_value(false)
                        .requires_all(&["language"])
                        .help(RECOVER_WALLET_HELP),
                )
                .arg(config_file_arg())
                .arg(consuming_wallet_arg())
                .arg(data_directory_arg())
                .arg(earning_wallet_arg(
                    EARNING_WALLET_HELP,
                    common_validators::validate_earning_wallet,
                ))
                .arg(language_arg())
                .arg(
                    Arg::with_name("mnemonic")
                        .long("mnemonic")
                        .value_name("MNEMONIC-WORDS")
                        .required(false)
                        .empty_values(false)
                        .require_delimiter(true)
                        .value_delimiter(" ")
                        .min_values(12)
                        .max_values(24)
                        //                        .validator(Validators::validate_mnemonic_word)
                        .help(MNEMONIC_HELP),
                )
                .arg(mnemonic_passphrase_arg())
                .arg(wallet_password_arg(WALLET_PASSWORD_HELP)),
        }
    }

    fn parse_args(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
        persistent_config: &PersistentConfiguration,
    ) -> WalletCreationConfig {
        if persistent_config.encrypted_mnemonic_seed().is_some() {
            panic!("Can't recover wallets: mnemonic seed has already been created")
        }
        self.make_wallet_creation_config(multi_config, streams)
    }

    fn request_mnemonic_passphrase(streams: &mut StdStreams) -> Option<String> {
        flushed_write(
            streams.stdout,
            "\nPlease enter the passphrase for your mnemonic, or Enter if there is none. You will \
             encrypt your wallet in a following step...\n",
        );
        flushed_write(streams.stdout, "Mnemonic passphrase: ");
        match request_existing_password(streams, |_| Ok(())) {
            Ok(mp) => {
                if mp.is_empty() {
                    None
                } else {
                    Some(mp)
                }
            }
            Err(e) => panic!("{:?}", e),
        }
    }

    fn get_mnemonic(
        language: Language,
        multi_config: &MultiConfig,
        streams: &mut StdStreams,
    ) -> Mnemonic {
        let phrase_words = {
            let arg_phrase_words = values_m!(multi_config, "mnemonic", String);
            if arg_phrase_words.is_empty() {
                Self::request_mnemonic_phrase(streams)
            } else {
                arg_phrase_words
            }
        };
        let phrase = phrase_words.join(" ");
        match Validators::validate_mnemonic_words(phrase.clone(), language) {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        }
        Mnemonic::from_phrase(phrase, language).expect("Error creating Mnemonic")
    }

    fn request_mnemonic_phrase(streams: &mut StdStreams) -> Vec<String> {
        flushed_write(streams.stdout, "\nPlease provide your wallet's mnemonic phrase. It must be 12, 15, 18, 21, or 24 words long.\n");
        flushed_write(streams.stdout, "Mnemonic phrase: ");
        let mut buf = [0u8; 16384];
        let phrase = match streams.stdin.read(&mut buf) {
            Ok(len) => String::from_utf8(Vec::from(&buf[0..len]))
                .expect("Mnemonic may not contain non-UTF-8 characters"),
            Err(e) => panic!("{:?}", e),
        };
        phrase.split(' ').map(|s| s.to_string()).collect()
    }
}

struct Validators {}

impl Validators {
    fn validate_mnemonic_words(phrase: String, language: Language) -> Result<(), String> {
        match Mnemonic::validate(phrase.as_str(), language) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!(
                "\"{}\" is not valid for {} ({})",
                phrase,
                Bip39::name_from_language(language),
                e
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::database::db_initializer;
    use crate::database::db_initializer::DbInitializer;
    use crate::multi_config::{CommandLineVCL, VirtualCommandLine};
    use crate::node_configurator::DerivationPathWalletInfo;
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::wallet::{
        DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
    };
    use crate::test_utils::ensure_node_home_directory_exists;
    use crate::test_utils::*;
    use bip39::Seed;
    use std::io::Cursor;

    #[test]
    fn validate_mnemonic_words_if_provided_in_chinese_simplified() {
        assert!(Validators::validate_mnemonic_words(
            "昨 据 肠 介 甘 橡 峰 冬 点 显 假 覆 归 了 曰 露 胀 偷 盆 缸 操 举 除 喜"
                .to_string(),
            Language::ChineseSimplified
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_chinese_traditional() {
        assert!(Validators::validate_mnemonic_words(
            "昨 據 腸 介 甘 橡 峰 冬 點 顯 假 覆 歸 了 曰 露 脹 偷 盆 缸 操 舉 除 喜"
                .to_string(),
            Language::ChineseTraditional
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_english() {
        assert!(Validators::validate_mnemonic_words(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold"
                .to_string(),
            Language::English
        )
        .is_ok());
    }

    #[test]
    fn fails_to_validate_nonsense_words_if_provided_in_english() {
        let phrase =
            "ooga booga gahooga zoo fail test twelve twenty four token smoke fire".to_string();
        let result = Validators::validate_mnemonic_words(phrase.clone(), Language::English);

        assert_eq!(
            result.unwrap_err(),
            format!(
                "\"{}\" is not valid for English (invalid word in phrase)",
                phrase
            )
        );
    }

    #[test]
    fn fails_to_validate_english_words_with_french() {
        let phrase =
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term \
            toddler sphere ripple idle dragon curious hold".to_string();
        let result = Validators::validate_mnemonic_words(phrase.clone(), Language::French);

        assert_eq!(
            result.unwrap_err(),
            format!(
                "\"{}\" is not valid for Français (invalid word in phrase)",
                phrase
            )
        );
    }

    #[test]
    fn fails_to_validate_sorted_wordlist_words_if_provided_in_english() {
        assert!(Validators::validate_mnemonic_words(
            "absent army cage curious dizzy dragon hawk hen hold idle kind lamp movie \
             pattern phone ripple shaft sphere tackle term timber toddler wide write"
                .to_string(),
            Language::English
        )
        .is_err());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_french() {
        assert!(Validators::validate_mnemonic_words(
            "stable bolide vignette fluvial ne\u{301}faste purifier muter lombric amour \
             de\u{301}cupler fouge\u{300}re silicium humble aborder vortex histoire somnoler \
             substrat rompre pivoter gendarme demeurer colonel frelon"
                .to_string(),
            Language::French
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_italian() {
        assert!(Validators::validate_mnemonic_words(
            "tampone bravura viola inodore poderoso scheda pimpante onice anca dote \
             intuito stizzoso mensola abolire zenzero massaia supporto taverna sistole riverso \
             lentezza ecco curatore ironico"
                .to_string(),
            Language::Italian
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_japanese() {
        assert!(Validators::validate_mnemonic_words(
            "まよう おおう るいせき しゃちょう てんし はっほ\u{309a}う てほと\u{3099}き た\u{3099}んな \
            いつか けいかく しゅらは\u{3099} ほけん そうか\u{3099}んきょう あきる ろんは\u{309a} せんぬき ほんき \
            みうち ひんは\u{309a}ん ねわさ\u{3099} すのこ け\u{3099}きとつ きふく し\u{3099}んし\u{3099}ゃ"
                .to_string(), Language::Japanese
        )
            .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_korean() {
        assert!(Validators::validate_mnemonic_words(
            "텔레비전 기법 확보 성당 음주 주문 유물 연휴 경주 무릎 세월 캐릭터 \
             신고 가르침 흐름 시중 큰아들 통장 창밖 전쟁 쇠고기 물가 마사지 소득"
                .to_string(),
            Language::Korean
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_spanish() {
        assert!(Validators::validate_mnemonic_words(
            "tarro bolero villa hacha opaco regalo oferta mochila amistad definir helio \
             suerte leer abono yeso lana taco tejado salto premio iglesia destino colcha himno"
                .to_string(),
            Language::Spanish
        )
        .is_ok());
    }

    #[test]
    fn parse_args_creates_configurations() {
        let home_dir = ensure_node_home_directory_exists(
            "node_configurator_recover_wallet",
            "parse_args_creates_configurations",
        );
        let password = "secret-wallet-password";
        let phrase = "llanto elipse chaleco factor setenta dental moneda rasgo gala rostro taco nudillo orador temor puesto";
        let consuming_path = "m/44'/60'/0'/77/78";
        let earning_path = "m/44'/60'/0'/78/77";
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--recover-wallet",
            "--config-file",
            "specified_config.toml",
            "--data-directory",
            home_dir.to_str().unwrap(),
            "--wallet-password",
            password,
            "--consuming-wallet",
            consuming_path,
            "--earning-wallet",
            earning_path,
            "--language",
            "español",
            "--mnemonic",
            phrase,
            "--mnemonic-passphrase",
            "Mortimer",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorRecoverWallet::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVCL::new(args))];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        let config = subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );

        let expected_mnemonic = Mnemonic::from_phrase(phrase, Language::Spanish).unwrap();
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: None,
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(
                        Seed::new(&expected_mnemonic, "Mortimer").as_ref()
                    ),
                    wallet_password: password.to_string(),
                    consuming_derivation_path_opt: Some(consuming_path.to_string()),
                    earning_derivation_path_opt: Some(earning_path.to_string())
                })
            },
        );
    }

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let password = "secret-wallet-password";
        let phrase = "company replace elder oxygen access into pair squeeze clip occur world crowd";
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--recover-wallet",
            "--wallet-password",
            password,
            "--mnemonic",
            phrase,
            "--mnemonic-passphrase",
            "Mortimer",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = NodeConfiguratorRecoverWallet::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVCL::new(args))];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        let config = subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );

        let expected_mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: None,
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(
                        Seed::new(&expected_mnemonic, "Mortimer").as_ref()
                    ),
                    wallet_password: password.to_string(),
                    consuming_derivation_path_opt: Some(
                        DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
                    ),
                    earning_derivation_path_opt: Some(DEFAULT_EARNING_DERIVATION_PATH.to_string())
                })
            },
        );
    }

    #[test]
    #[should_panic(
        expected = "\"one two three four five six seven eight nine ten eleven twelve\" is not valid for English (invalid word in phrase)"
    )]
    fn mnemonic_argument_fails_with_invalid_words() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--recover-wallet",
            "--mnemonic",
            "one two three four five six seven eight nine ten eleven twelve",
            "--wallet-password",
            "wallet-password",
            "--mnemonic-passphrase",
            "mnemonic passphrase",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let subject = NodeConfiguratorRecoverWallet::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );
    }

    #[test]
    fn request_mnemonic_passphrase_happy_path() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"a very poor passphrase\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = NodeConfiguratorRecoverWallet::request_mnemonic_passphrase(streams);

        assert_eq!(actual, Some("a very poor passphrase".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease enter the passphrase for your mnemonic, or Enter if there is none. \
             You will encrypt your wallet in a following step...\n\
             Mnemonic passphrase: "
                .to_string()
        );
    }

    #[test]
    fn request_mnemonic_passphrase_given_blank_is_allowed_with_no_scolding() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = NodeConfiguratorRecoverWallet::request_mnemonic_passphrase(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease enter the passphrase for your mnemonic, or Enter if there is none. \
             You will encrypt your wallet in a following step...\n\
             Mnemonic passphrase: "
                .to_string()
        );
    }

    #[test]
    #[should_panic(expected = "Can't recover wallets: mnemonic seed has already been created")]
    fn preexisting_mnemonic_seed_causes_collision_and_panics() {
        let data_directory = ensure_node_home_directory_exists(
            "node_configurator_recover_wallet",
            "preexisting_mnemonic_seed_causes_collision_and_panics",
        );

        let conn = db_initializer::DbInitializerReal::new()
            .initialize(&data_directory)
            .unwrap();
        let config_dao = ConfigDaoReal::new(conn);
        config_dao.set_string("seed", "booga booga").unwrap();
        let args = vec![
            "SubstratumNode",
            "--recover-wallet",
            "--data-directory",
            data_directory.to_str().unwrap(),
            "--wallet-password",
            "rick-rolled",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();
        let subject = NodeConfiguratorRecoverWallet::new();
        let vcl = Box::new(CommandLineVCL::new(args));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &PersistentConfigurationReal::new(Box::new(config_dao)),
        );
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn configure_senses_when_user_specifies_config_file() {
        let subject = NodeConfiguratorRecoverWallet::new();
        let args = vec![
            "SubstratumNode",
            "--config-file",
            "booga.toml", // nonexistent config file: should stimulate panic because user-specified
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();
        subject.configure(&args, &mut FakeStreamHolder::new().streams());
    }
}
