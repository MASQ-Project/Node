// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::database::config_dumper;
use crate::node_configurator::node_configurator_generate_wallet::NodeConfiguratorGenerateWallet;
use crate::node_configurator::node_configurator_recover_wallet::NodeConfiguratorRecoverWallet;
use crate::node_configurator::{NodeConfigurator, WalletCreationConfig};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::server_initializer::ServerInitializer;
use crate::sub_lib::main_tools::{Command, StdStreams};
use actix::System;
use futures::future::Future;

#[derive(Debug, PartialEq)]
enum Mode {
    GenerateWallet,
    RecoverWallet,
    DumpConfig,
    RunTheNode,
}

pub fn go(args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
    match determine_mode(args) {
        Mode::GenerateWallet => generate_wallet(args, streams),
        Mode::RecoverWallet => recover_wallet(args, streams),
        Mode::DumpConfig => dump_config(args, streams),
        Mode::RunTheNode => run_the_node(args, streams),
    }
}

fn determine_mode(args: &Vec<String>) -> Mode {
    if args.contains(&"--dump-config".to_string()) {
        Mode::DumpConfig
    } else if args.contains(&"--recover-wallet".to_string()) {
        Mode::RecoverWallet
    } else if args.contains(&"--generate-wallet".to_string()) {
        Mode::GenerateWallet
    } else {
        Mode::RunTheNode
    }
}

fn run_the_node(args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
    let system = System::new("main");

    let mut server_initializer = ServerInitializer::new();
    server_initializer.go(streams, args);

    actix::spawn(server_initializer.map_err(|_| {
        System::current().stop_with_code(1);
    }));

    system.run()
}

fn generate_wallet(args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
    let configurator = NodeConfiguratorGenerateWallet::new();
    configuration_run(args, streams, &configurator)
}

fn recover_wallet(args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
    let configurator = NodeConfiguratorRecoverWallet::new();
    configuration_run(args, streams, &configurator)
}

fn dump_config(args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
    config_dumper::dump_config(args, streams)
}

fn configuration_run(
    args: &Vec<String>,
    streams: &mut StdStreams<'_>,
    configurator: &dyn NodeConfigurator<WalletCreationConfig>,
) -> i32 {
    let config = configurator.configure(args, streams);
    PrivilegeDropperReal::new().drop_privileges(&config.real_user);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_wallet() {
        [["--generate-wallet"]]
            .into_iter()
            .for_each(|args| check_mode(args, Mode::GenerateWallet));
    }

    #[test]
    fn recover_wallet() {
        [["--recover-wallet"]]
            .into_iter()
            .for_each(|args| check_mode(args, Mode::RecoverWallet));
    }

    #[test]
    fn dump_config() {
        [["--dump-config"]]
            .into_iter()
            .for_each(|args| check_mode(args, Mode::DumpConfig));
    }

    #[test]
    fn both_generate_and_recover() {
        [
            ["--generate-wallet", "--recover-wallet"],
            ["--recover-wallet", "--generate-wallet"],
        ]
        .into_iter()
        .for_each(|args| check_mode(args, Mode::RecoverWallet));
    }

    #[test]
    fn dump_config_rules_all() {
        [
            ["--booga", "--generate-wallet", "--dump-config"],
            ["--booga", "--recover-wallet", "--dump-config"],
            ["--generate-wallet", "--recover_wallet", "--dump-config"],
        ]
        .into_iter()
        .for_each(|args| check_mode(args, Mode::DumpConfig));
    }

    #[test]
    fn run_servers() {
        check_mode(&[], Mode::RunTheNode)
    }

    fn check_mode(args: &[&str], expected_mode: Mode) {
        let mut augmented_args: Vec<&str> = vec!["--unrelated"];
        augmented_args.extend(args);
        augmented_args.push("--unrelated");
        let args = strs_to_strings(augmented_args);

        let actual_mode = determine_mode(&args);

        assert_eq!(actual_mode, expected_mode);
    }

    fn strs_to_strings(strs: Vec<&str>) -> Vec<String> {
        strs.into_iter().map(|str| str.to_string()).collect()
    }
}
