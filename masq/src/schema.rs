// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::change_password_command::{
    change_password_subcommand, set_password_subcommand,
};
use crate::commands::check_password_command::check_password_subcommand;
use crate::commands::configuration_command::configuration_subcommand;
use crate::commands::connection_status_command::connection_status_subcommand;
use crate::commands::crash_command::crash_subcommand;
use crate::commands::descriptor_command::descriptor_subcommand;
use crate::commands::financials_command::args_validation::financials_subcommand;
use crate::commands::generate_wallets_command::generate_wallets_subcommand;
use crate::commands::recover_wallets_command::recover_wallets_subcommand;
use crate::commands::scan_command::scan_subcommand;
use crate::commands::set_configuration_command::set_configuration_subcommand;
use crate::commands::setup_command::setup_subcommand;
use crate::commands::shutdown_command::shutdown_subcommand;
use crate::commands::start_command::start_subcommand;
use crate::commands::wallet_addresses_command::wallet_addresses_subcommand;
use clap::{App, AppSettings, Arg};
use lazy_static::lazy_static;
use masq_lib::constants::{DEFAULT_UI_PORT, HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use crate::commands::neighborhood_info_command::neighborhood_info_subcommand;

lazy_static! {
    static ref UI_PORT_HELP: String = format!(
        "If the Daemon is listening for connections at some port other than {}, specify that port \
         here. Must be between {} and {}.",
        DEFAULT_UI_PORT, LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    static ref DEFAULT_UI_PORT_STRING: String = format!("{}", DEFAULT_UI_PORT);
}

const APP_NAME: &str = "masq";
const APP_VERSION: &str = "1.0.0";
const APP_AUTHOR: &str = "MASQ";
const APP_ABOUT: &str =
    "masq is a command-line user interface to the MASQ Daemon and the MASQ Node";

pub fn app_head() -> App<'static, 'static> {
    App::new(APP_NAME)
        .global_settings(if cfg!(test) {
            &[AppSettings::ColorNever]
        } else {
            &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
        })
        //.version(crate_version!())
        //.author(crate_authors!("\n")) // TODO: Put this back in when clap is compatible with Rust 1.38.0
        .version(APP_VERSION)
        .author(APP_AUTHOR)
        .about(APP_ABOUT)
}

pub fn app() -> App<'static, 'static> {
    app_head()
        .arg(
            Arg::with_name("ui-port")
                .long("ui-port")
                .value_name("UI-PORT")
                .takes_value(true)
                .default_value(DEFAULT_UI_PORT_STRING.as_str())
                .validator(validate_ui_port)
                .help(UI_PORT_HELP.as_str()),
        )
        .subcommand(change_password_subcommand())
        .subcommand(check_password_subcommand())
        .subcommand(crash_subcommand())
        .subcommand(configuration_subcommand())
        .subcommand(connection_status_subcommand())
        .subcommand(descriptor_subcommand())
        .subcommand(financials_subcommand())
        .subcommand(generate_wallets_subcommand())
        .subcommand(neighborhood_info_subcommand())
        .subcommand(recover_wallets_subcommand())
        .subcommand(scan_subcommand())
        .subcommand(set_configuration_subcommand())
        .subcommand(set_password_subcommand())
        .subcommand(setup_subcommand())
        .subcommand(shutdown_subcommand())
        .subcommand(start_subcommand())
        .subcommand(wallet_addresses_subcommand())
}

fn validate_ui_port(port: String) -> Result<(), String> {
    match str::parse::<u16>(&port) {
        Ok(p) if p < LOWEST_USABLE_INSECURE_PORT => Err(format!("{}", p)),
        Ok(_) => Ok(()),
        Err(_) => Err(port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(APP_NAME, "masq");
        assert_eq!(APP_VERSION, "1.0.0");
        assert_eq!(APP_AUTHOR, "MASQ");
        assert_eq!(
            APP_ABOUT,
            "masq is a command-line user interface to the MASQ Daemon and the MASQ Node"
        );
        assert_eq!(
            UI_PORT_HELP.to_string(),
            format!(
                "If the Daemon is listening for connections at some port other than {}, specify that port \
                 here. Must be between {} and {}.",
                DEFAULT_UI_PORT, LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
            )
        );
        assert_eq!(
            DEFAULT_UI_PORT_STRING.to_string(),
            format!("{}", DEFAULT_UI_PORT)
        );
    }
}
