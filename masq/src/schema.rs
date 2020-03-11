// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::commands::{setup_subcommand, shutdown_subcommand, start_subcommand};
use clap::{crate_description, crate_version, App, AppSettings, Arg};
use lazy_static::lazy_static;
use masq_lib::constants::{DEFAULT_UI_PORT, HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};

lazy_static! {
    static ref UI_PORT_HELP: String = format!(
        "If the Daemon is listening for connections at some port other than {}, specify that port \
         here. Must be between {} and {}.",
        DEFAULT_UI_PORT, LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
    static ref DEFAULT_UI_PORT_STRING: String = format!("{}", DEFAULT_UI_PORT);
}

pub fn app_head() -> App<'static, 'static> {
    App::new("MASQNode")
        .global_settings(if cfg!(test) {
            &[AppSettings::ColorNever]
        } else {
            &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
        })
        .version(crate_version!())
        //        .author(crate_authors!("\n")) // TODO: Put this back in when clap is compatible with Rust 1.38.0
        .author("Substratum, MASQ")
        .about(crate_description!())
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
        .subcommand(setup_subcommand())
        .subcommand(start_subcommand())
        .subcommand(shutdown_subcommand())
}

fn validate_ui_port(port: String) -> Result<(), String> {
    match str::parse::<u16>(&port) {
        Ok(p) if p < LOWEST_USABLE_INSECURE_PORT => Err(format!("{}", p)),
        Ok(_) => Ok(()),
        Err(_) => Err(port),
    }
}
