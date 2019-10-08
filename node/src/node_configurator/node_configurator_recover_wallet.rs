// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::bip39::Bip39;
use crate::multi_config::MultiConfig;
use crate::node_configurator::{
    app_head, chain_arg, common_validators, consuming_wallet_arg, create_wallet,
    data_directory_arg, earning_wallet_arg, exit, flushed_write, language_arg,
    mnemonic_passphrase_arg, prepare_initialization_mode, real_user_arg,
    request_password_with_confirmation, request_password_with_retry, wallet_password_arg, Either,
    NodeConfigurator, WalletCreationConfig, WalletCreationConfigMaker, EARNING_WALLET_HELP,
    WALLET_PASSWORD_HELP,
};
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::main_tools::StdStreams;
use bip39::{Language, Mnemonic};
use clap::{value_t, values_t, App, Arg};
use indoc::indoc;

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_USABLE_PORT: u16 = 65535;

pub struct NodeConfiguratorRecoverWallet {
    app: App<'static, 'static>,
}

impl NodeConfigurator<WalletCreationConfig> for NodeConfiguratorRecoverWallet {
    fn configure(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> WalletCreationConfig {
        let (multi_config, persistent_config_box) = prepare_initialization_mode(&self.app, args);
        let persistent_config = persistent_config_box.as_ref();

        let config = self.parse_args(&multi_config, streams, persistent_config);

        create_wallet(&config, persistent_config);

        config
    }
}

const RECOVER_WALLET_HELP: &str =
    "Import an existing set of HD wallets with mnemonic recovery phrase from the standard \
     BIP39 predefined list of words. Not valid as an environment variable.";
const MNEMONIC_HELP: &str =
    "An HD wallet mnemonic recovery phrase using predefined BIP39 word lists. This is a secret; providing it on the \
     command line or in a config file is insecure and unwise. If you don't specify it anywhere, you'll be prompted \
     for it at the console. If you do specify it on the command line or in the environment or a config file, be sure \
     to surround it with double quotes.";

const HELP_TEXT: &str = indoc!(
    r"ADDITIONAL HELP:
    If you want to generate wallets to earn money into and spend money from, try:

        MASQNode --help --generate-wallet

    If the Node is already configured with your wallets, and you want to start the Node so that it
    stays running:

        MASQNode --help"
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
            app: app_head()
                .after_help(HELP_TEXT)
                .arg(
                    Arg::with_name("recover-wallet")
                        .long("recover-wallet")
                        .required(true)
                        .takes_value(false)
                        .requires_all(&["language"])
                        .help(RECOVER_WALLET_HELP),
                )
                .arg(chain_arg())
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
                        .help(MNEMONIC_HELP),
                )
                .arg(mnemonic_passphrase_arg())
                .arg(real_user_arg())
                .arg(wallet_password_arg(WALLET_PASSWORD_HELP)),
        }
    }

    fn parse_args(
        &self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
        persistent_config: &dyn PersistentConfiguration,
    ) -> WalletCreationConfig {
        if persistent_config.encrypted_mnemonic_seed().is_some() {
            exit(
                1,
                "Can't recover wallets: mnemonic seed has already been created",
            );
        }
        self.make_wallet_creation_config(multi_config, streams)
    }

    fn request_mnemonic_passphrase(streams: &mut StdStreams) -> Option<String> {
        flushed_write(
            streams.stdout,
            "\nPlease enter the passphrase for your mnemonic, or Enter if there is none.\n\
             You will encrypt your wallet in a following step...\n",
        );
        match request_password_with_retry("  Mnemonic passphrase: ", streams, |streams| {
            request_password_with_confirmation(
                "  Confirm mnemonic passphrase: ",
                "\nPassphrases do not match.",
                streams,
                |_| Ok(()),
            )
        }) {
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
            Err(e) => exit(1, &e),
        }
        Mnemonic::from_phrase(phrase, language).expect("Error creating Mnemonic")
    }

    fn request_mnemonic_phrase(streams: &mut StdStreams) -> Vec<String> {
        flushed_write(streams.stdout, "\nPlease provide your wallet's mnemonic phrase.\nIt must be 12, 15, 18, 21, or 24 words long.\n");
        flushed_write(streams.stdout, "Mnemonic phrase: ");
        let mut buf = [0u8; 16384];
        let phrase = match streams.stdin.read(&mut buf) {
            Ok(len) => String::from_utf8(Vec::from(&buf[0..len]))
                .expect("Mnemonic may not contain non-UTF-8 characters"),
            Err(e) => panic!("{:?}", e),
        };
        phrase
            .split(|c| " \t\n".contains(c))
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect()
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
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_interface::DEFAULT_CHAIN_NAME;
    use crate::bootstrapper::RealUser;
    use crate::config_dao::{ConfigDao, ConfigDaoReal};
    use crate::database::db_initializer;
    use crate::database::db_initializer::DbInitializer;
    use crate::multi_config::{CommandLineVcl, VirtualCommandLine};
    use crate::node_configurator::DerivationPathWalletInfo;
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::wallet::{
        Wallet, DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
    };
    use crate::test_utils::ensure_node_home_directory_exists;
    use crate::test_utils::*;
    use bip39::Seed;
    use std::io::Cursor;

    #[test]
    fn validate_mnemonic_words_if_provided_in_chinese_simplified() {
        assert!(Validators::validate_mnemonic_words(
            "昨 据 肠 介 甘 橡 峰 冬 点 显 假 覆 归 了 曰 露 胀 偷 盆 缸 操 举 除 喜".to_string(),
            Language::ChineseSimplified,
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_chinese_traditional() {
        assert!(Validators::validate_mnemonic_words(
            "昨 據 腸 介 甘 橡 峰 冬 點 顯 假 覆 歸 了 曰 露 脹 偷 盆 缸 操 舉 除 喜".to_string(),
            Language::ChineseTraditional,
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_english() {
        assert!(Validators::validate_mnemonic_words(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold"
                .to_string(),
            Language::English,
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
            Language::English,
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
            Language::French,
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
            Language::Italian,
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_japanese() {
        assert!(Validators::validate_mnemonic_words(
            "まよう おおう るいせき しゃちょう てんし はっほ\u{309a}う てほと\u{3099}き た\u{3099}んな \
            いつか けいかく しゅらは\u{3099} ほけん そうか\u{3099}んきょう あきる ろんは\u{309a} せんぬき ほんき \
            みうち ひんは\u{309a}ん ねわさ\u{3099} すのこ け\u{3099}きとつ きふく し\u{3099}んし\u{3099}ゃ"
                .to_string(), Language::Japanese,
        )
            .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_korean() {
        assert!(Validators::validate_mnemonic_words(
            "텔레비전 기법 확보 성당 음주 주문 유물 연휴 경주 무릎 세월 캐릭터 \
             신고 가르침 흐름 시중 큰아들 통장 창밖 전쟁 쇠고기 물가 마사지 소득"
                .to_string(),
            Language::Korean,
        )
        .is_ok());
    }

    #[test]
    fn validate_mnemonic_words_if_provided_in_spanish() {
        assert!(Validators::validate_mnemonic_words(
            "tarro bolero villa hacha opaco regalo oferta mochila amistad definir helio \
             suerte leer abono yeso lana taco tejado salto premio iglesia destino colcha himno"
                .to_string(),
            Language::Spanish,
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
        let args = ArgsBuilder::new()
            .opt("--recover-wallet")
            .param("--chain", DEFAULT_CHAIN_NAME)
            .param("--data-directory", home_dir.to_str().unwrap())
            .param("--wallet-password", password)
            .param("--consuming-wallet", consuming_path)
            .param("--earning-wallet", earning_path)
            .param("--language", "español")
            .param("--mnemonic", phrase)
            .param("--mnemonic-passphrase", "Mortimer")
            .param("--real-user", "123:456:/home/booga");
        let subject = NodeConfiguratorRecoverWallet::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        let config = subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );

        let expected_mnemonic = Mnemonic::from_phrase(phrase, Language::Spanish).unwrap();
        let seed = Seed::new(&expected_mnemonic, "Mortimer");
        let earning_wallet =
            Wallet::from(Bip32ECKeyPair::from_raw(seed.as_ref(), earning_path).unwrap());
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: Some(earning_wallet.to_string()),
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(
                        Seed::new(&expected_mnemonic, "Mortimer").as_ref()
                    ),
                    wallet_password: password.to_string(),
                    consuming_derivation_path_opt: Some(consuming_path.to_string()),
                }),
                real_user: RealUser::new(Some(123), Some(456), Some("/home/booga".into()))
            },
        );
    }

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let password = "secret-wallet-password";
        let phrase = "company replace elder oxygen access into pair squeeze clip occur world crowd";
        let args = ArgsBuilder::new()
            .opt("--recover-wallet")
            .param("--chain", DEFAULT_CHAIN_NAME)
            .param("--wallet-password", password)
            .param("--mnemonic", phrase)
            .param("--mnemonic-passphrase", "Mortimer");
        let subject = NodeConfiguratorRecoverWallet::new();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::new(&subject.app, vcls);

        let config = subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &make_default_persistent_configuration(),
        );

        let expected_mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&expected_mnemonic, "Mortimer");
        let earning_wallet = Wallet::from(
            Bip32ECKeyPair::from_raw(seed.as_ref(), DEFAULT_EARNING_DERIVATION_PATH).unwrap(),
        );
        assert_eq!(
            config,
            WalletCreationConfig {
                earning_wallet_address_opt: Some(earning_wallet.to_string()),
                derivation_path_info_opt: Some(DerivationPathWalletInfo {
                    mnemonic_seed: PlainData::new(seed.as_ref()),
                    wallet_password: password.to_string(),
                    consuming_derivation_path_opt: Some(
                        DEFAULT_CONSUMING_DERIVATION_PATH.to_string()
                    ),
                }),
                real_user: RealUser::null(),
            },
        );
    }

    #[test]
    #[should_panic(
        expected = "\"one two three four five six seven eight nine ten eleven twelve\" is not valid for English (invalid word in phrase)"
    )]
    fn mnemonic_argument_fails_with_invalid_words() {
        let args = ArgsBuilder::new()
            .opt("--recover-wallet")
            .param("--chain", DEFAULT_CHAIN_NAME)
            .param(
                "--mnemonic",
                "one two three four five six seven eight nine ten eleven twelve",
            )
            .param("--wallet-password", "wallet-password")
            .param("--mnemonic-passphrase", "mnemonic passphrase");
        let subject = NodeConfiguratorRecoverWallet::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
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
            stdin: &mut Cursor::new(&b"a very poor passphrase\na very poor passphrase\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = NodeConfiguratorRecoverWallet::request_mnemonic_passphrase(streams);

        assert_eq!(actual, Some("a very poor passphrase".to_string()));
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease enter the passphrase for your mnemonic, or Enter if there is none.\n\
             You will encrypt your wallet in a following step...\n  Mnemonic passphrase:   \
             Confirm mnemonic passphrase: "
                .to_string()
        );
    }

    #[test]
    fn request_mnemonic_passphrase_sad_path() {
        let stdout_writer = &mut ByteArrayWriter::new();
        let streams = &mut StdStreams {
            stdin: &mut Cursor::new(&b"a very great passphrase\na very poor passphrase\n"[..]),
            stdout: stdout_writer,
            stderr: &mut ByteArrayWriter::new(),
        };

        let actual = NodeConfiguratorRecoverWallet::request_mnemonic_passphrase(streams);

        assert_eq!(actual, None);
        assert_eq!(
            stdout_writer.get_string(),
            "\nPlease enter the passphrase for your mnemonic, or Enter if there is none.\n\
             You will encrypt your wallet in a following step...\n  Mnemonic passphrase:   \
             Confirm mnemonic passphrase: \nPassphrases do not match. Try again.\n  Mnemonic passphrase:   Confirm mnemonic passphrase: \nWhile ill-advised, proceeding with no mnemonic passphrase.\nPress Enter to continue..."
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
            "\nPlease enter the passphrase for your mnemonic, or Enter if there is none.\n\
             You will encrypt your wallet in a following step...\n  Mnemonic passphrase:   \
             Confirm mnemonic passphrase: \
             \nWhile ill-advised, proceeding with no mnemonic passphrase.\
             \nPress Enter to continue..."
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
            .initialize(&data_directory, DEFAULT_CHAIN_ID)
            .unwrap();
        let config_dao = ConfigDaoReal::new(conn);
        config_dao.set_string("seed", "booga booga").unwrap();
        let args = ArgsBuilder::new()
            .opt("--recover-wallet")
            .param("--chain", DEFAULT_CHAIN_NAME)
            .param("--data-directory", data_directory.to_str().unwrap())
            .param("--wallet-password", "rick-rolled");
        let subject = NodeConfiguratorRecoverWallet::new();
        let vcl = Box::new(CommandLineVcl::new(args.into()));
        let multi_config = MultiConfig::new(&subject.app, vec![vcl]);

        subject.parse_args(
            &multi_config,
            &mut FakeStreamHolder::new().streams(),
            &PersistentConfigurationReal::new(Box::new(config_dao)),
        );
    }

    #[test]
    fn request_mnemonic_phrase_happy_path() {
        let phrase = "aim special peace\t stumble torch   spatial timber \t \tpayment lunar\tworld\tpretty high\n";
        let mut streams = StdStreams {
            stdin: &mut Cursor::new(phrase.as_bytes()),
            stdout: &mut ByteArrayWriter::new(),
            stderr: &mut ByteArrayWriter::new(),
        };

        let result = NodeConfiguratorRecoverWallet::request_mnemonic_phrase(&mut streams);

        assert_eq!(
            result,
            vec![
                "aim".to_string(),
                "special".to_string(),
                "peace".to_string(),
                "stumble".to_string(),
                "torch".to_string(),
                "spatial".to_string(),
                "timber".to_string(),
                "payment".to_string(),
                "lunar".to_string(),
                "world".to_string(),
                "pretty".to_string(),
                "high".to_string(),
            ]
        )
    }
}
