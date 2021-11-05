// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use clap::{crate_description, App, AppSettings, Arg};
use indoc::indoc;
use lazy_static::lazy_static;
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use masq_lib::shared_schema::{
    chain_arg, data_directory_arg, db_password_arg, real_user_arg, shared_app, ui_port_arg,
    DB_PASSWORD_HELP,
};

pub fn app_head() -> App<'static, 'static> {
    App::new("MASQNode")
        .global_settings(if cfg!(test) {
            &[AppSettings::ColorNever]
        } else {
            &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
        })
        //.version(crate_version!())
        .version("1.0.0")
        .author("MASQ")
        .about(crate_description!())
}

pub fn app_daemon() -> App<'static, 'static> {
    app_head()
        .arg(
            Arg::with_name("initialization")
                .long("initialization")
                .required(true)
                .takes_value(false)
                .help("Directs MASQ to start the Daemon that controls the Node, rather than the Node itself"),
        )
        .arg(ui_port_arg(&DAEMON_UI_PORT_HELP))
}

pub fn app_node() -> App<'static, 'static> {
    shared_app(app_head().after_help(NODE_HELP_TEXT)).arg(ui_port_arg(&DAEMON_UI_PORT_HELP))
}

pub fn app_config_dumper() -> App<'static, 'static> {
    app_head()
        .arg(
            Arg::with_name("dump-config")
                .long("dump-config")
                .required(true)
                .takes_value(false)
                .help(DUMP_CONFIG_HELP),
        )
        .arg(chain_arg())
        .arg(data_directory_arg())
        .arg(real_user_arg())
        .arg(db_password_arg(DB_PASSWORD_HELP))
}

lazy_static! {
    static ref DAEMON_UI_PORT_HELP: String = format!(
        "The port at which user interfaces will connect to the Daemon. (This is NOT the port at which \
        interfaces will connect to the Node: no one will know that until after the Node starts.) \
        Best to accept the default unless you know what you're doing. Must be between {} and {}.",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
}

const DUMP_CONFIG_HELP: &str =
    "Dump the configuration of MASQ Node to stdout in JSON. Used chiefly by UIs.";

const NODE_HELP_TEXT: &str = indoc!(
    r"ADDITIONAL HELP:
    If you want to start the MASQ Daemon to manage the MASQ Node and the MASQ UIs, try:

        MASQNode --help --initialization

    If you want to dump the contents of the configuration table in the database so that
    you can see what's in it, try:

        MASQNode --help --dump-config

    MASQ Node listens for connections from other Nodes using the computer's
    network interface. Configuring the internet router for port forwarding is a necessary
    step for Node users to permit network communication between Nodes.

    Once started, Node prints the node descriptor to the console. The descriptor
    indicates the required port needing to be forwarded by the network router. The port is
    the last number in the descriptor, as shown below:

        masq://eth-mainnet:6hXbJTZWUKboREQsEMl9iQxsjRz6LQxh-zGZmGCvA3k@86.75.30.9:1234
                                                                                  ^^^^

    Steps To Forwarding Ports In The Router
        1. Log in to the router.
        2. Navigate to the router's port forwarding section, also frequently called virtual server.
        3. Create the port forwarding entries in the router."
);
