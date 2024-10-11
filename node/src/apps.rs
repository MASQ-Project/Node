// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use clap::{crate_description, crate_version, App, AppSettings, Arg};
use indoc::indoc;
use lazy_static::lazy_static;
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use masq_lib::shared_schema::{
    chain_arg, data_directory_arg, db_password_arg, real_user_arg, shared_app, ui_port_arg,
    DATA_DIRECTORY_HELP, DB_PASSWORD_HELP,
};
use masq_lib::utils::DATA_DIRECTORY_DAEMON_HELP;

pub fn app_head() -> App<'static, 'static> {
    App::new("MASQNode")
        .global_settings(if cfg!(test) {
            &[AppSettings::ColorNever]
        } else {
            &[AppSettings::ColorAuto, AppSettings::ColoredHelp]
        })
        .version(crate_version!())
        .author("MASQ")
        .about(crate_description!())
}

pub fn app_daemon() -> App<'static, 'static> {
    app_head()
        .arg(data_directory_arg(DATA_DIRECTORY_DAEMON_HELP.as_str()))
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
    shared_app(app_head().after_help(NODE_HELP_TEXT))
        .arg(data_directory_arg(DATA_DIRECTORY_HELP.as_str()))
        .arg(ui_port_arg(&DAEMON_UI_PORT_HELP))
}

pub fn app_config_dumper() -> App<'static, 'static> {
    app_head()
        .arg(chain_arg())
        .arg(
            Arg::with_name("dump-config")
                .long("dump-config")
                .required(true)
                .takes_value(false)
                .help(DUMP_CONFIG_HELP),
        )
        .arg(data_directory_arg(DATA_DIRECTORY_DAEMON_HELP.as_str()))
        .arg(db_password_arg(DB_PASSWORD_HELP))
        .arg(real_user_arg())
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

#[cfg(test)]
mod tests {
    use super::*;
    use dirs::{data_local_dir, home_dir};
    use std::path::Path;

    #[test]
    fn constants_have_correct_values() {
        let data_dir = data_local_dir().unwrap();
        let home_dir = home_dir().unwrap();
        let polygon_mainnet_dir = Path::new(&data_dir.to_str().unwrap())
            .join("MASQ")
            .join("polygon-mainnet");
        let polygon_mumbai_dir = Path::new(&data_dir.to_str().unwrap())
            .join("MASQ")
            .join("polygon-mumbai");

        assert_eq!(
            DATA_DIRECTORY_DAEMON_HELP.as_str(),
            format!("Directory in which the Node will store its persistent state, including at least its database \
            and by default its configuration file as well. By default, your data-directory is located in \
            your application directory, under your home directory e.g.: '{}'.\n\n\
            In case you change your chain to a different one, the data-directory path is automatically changed \
            to end with the name of your chain: e.g.: if you choose polygon-mumbai, then data-directory is \
            automatically changed to: '{}'.\n\n\
            You can specify your own data-directory to the Daemon in two different ways: \n\n\
            1. If you provide a path without the chain name on the end, the Daemon will automatically change \
            your data-directory to correspond with the chain. For example: {}/masq_home will be automatically \
            changed to: '{}/masq_home/polygon-mainnet'.\n\n\
            2. If you provide your data directory with the corresponding chain name on the end, eg: {}/masq_home/polygon-mainnet, \
            there will be no change until you set the chain parameter to a different value.",
            polygon_mainnet_dir.to_string_lossy().to_string().as_str(),
            polygon_mumbai_dir.to_string_lossy().to_string().as_str(),
            &home_dir.to_string_lossy().to_string().as_str(),
            &home_dir.to_string_lossy().to_string().as_str(),
            home_dir.to_string_lossy().to_string().as_str()
            )
        );
        assert_eq!(
            DUMP_CONFIG_HELP,
            "Dump the configuration of MASQ Node to stdout in JSON. Used chiefly by UIs."
        );
        assert_eq!(
            NODE_HELP_TEXT,
            indoc!(
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
            )
        );
        assert_eq!(
            DAEMON_UI_PORT_HELP.as_str(),
            &format!(
                "The port at which user interfaces will connect to the Daemon. (This is NOT the port at which \
                 interfaces will connect to the Node: no one will know that until after the Node starts.) \
                 Best to accept the default unless you know what you're doing. Must be between {} and {}.",
                LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
            )
        );
    }
}
