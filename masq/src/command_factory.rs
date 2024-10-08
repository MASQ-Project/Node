// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::check_password_command::CheckPasswordCommand;
use crate::commands::commands_common::Command;
use crate::commands::configuration_command::ConfigurationCommand;
use crate::commands::connection_status_command::ConnectionStatusCommand;
use crate::commands::crash_command::CrashCommand;
use crate::commands::descriptor_command::DescriptorCommand;
use crate::commands::financials_command::FinancialsCommand;
use crate::commands::generate_wallets_command::GenerateWalletsCommand;
use crate::commands::recover_wallets_command::RecoverWalletsCommand;
use crate::commands::scan_command::ScanCommand;
use crate::commands::set_configuration_command::SetConfigurationCommand;
use crate::commands::set_exit_location_command::SetExitLocationCommand;
use crate::commands::setup_command::SetupCommand;
use crate::commands::shutdown_command::ShutdownCommand;
use crate::commands::start_command::StartCommand;
use crate::commands::wallet_addresses_command::WalletAddressesCommand;

#[derive(Debug, PartialEq, Eq)]
pub enum CommandFactoryError {
    UnrecognizedSubcommand(String),
    CommandSyntax(String),
}

pub trait CommandFactory {
    fn make(&self, pieces: &[String]) -> Result<Box<dyn Command>, CommandFactoryError>;
}

#[derive(Default)]
pub struct CommandFactoryReal;

impl CommandFactory for CommandFactoryReal {
    fn make(&self, pieces: &[String]) -> Result<Box<dyn Command>, CommandFactoryError> {
        let boxed_command: Box<dyn Command> = match pieces[0].as_str() {
            "change-password" => match ChangePasswordCommand::new_change(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "check-password" => match CheckPasswordCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "configuration" => match ConfigurationCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "connection-status" => Box::new(ConnectionStatusCommand::new()),
            "crash" => match CrashCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "descriptor" => Box::new(DescriptorCommand::new()),
            "exit-location" => match SetExitLocationCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "financials" => match FinancialsCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "generate-wallets" => match GenerateWalletsCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "recover-wallets" => match RecoverWalletsCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "scan" => match ScanCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "set-configuration" => match SetConfigurationCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "set-password" => match ChangePasswordCommand::new_set(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "setup" => match SetupCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "shutdown" => Box::new(ShutdownCommand::new()),
            "start" => Box::new(StartCommand::new()),
            "wallet-addresses" => match WalletAddressesCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            unrecognized => return Err(UnrecognizedSubcommand(unrecognized.to_string())),
        };
        Ok(boxed_command)
    }
}

impl CommandFactoryReal {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::CommandFactoryError::UnrecognizedSubcommand;
    use masq_lib::messages::CountryCodes;

    #[test]
    fn complains_about_unrecognized_subcommand() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&["booga".to_string(), "agoob".to_string()])
            .err()
            .unwrap();

        assert_eq!(result, UnrecognizedSubcommand("booga".to_string()));
    }

    #[test]
    fn factory_produces_change_password() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(&[
                "change-password".to_string(),
                "abracadabra".to_string(),
                "boringPassword".to_string(),
            ])
            .unwrap();

        assert_eq!(
            command
                .as_any()
                .downcast_ref::<ChangePasswordCommand>()
                .unwrap(),
            &ChangePasswordCommand {
                old_password: Some("abracadabra".to_string()),
                new_password: "boringPassword".to_string()
            }
        );
    }

    #[test]
    fn factory_complains_about_change_password_with_one_parameter() {
        let subject = CommandFactoryReal::new();
        let result = subject
            .make(&["change-password".to_string(), "abracadabra".to_string()])
            .err()
            .unwrap();

        let err = match result {
            CommandFactoryError::CommandSyntax(s) => s,
            x => panic!("Expected CommandSyntax error; got {:?}", x),
        };
        assert_eq!(
            err.contains("The following required arguments were not provided"),
            true,
            "{}",
            err
        );
    }

    #[test]
    fn factory_produces_check_password() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&["check-password".to_string(), "bonkers".to_string()])
            .unwrap();

        let check_password_command: &CheckPasswordCommand = result.as_any().downcast_ref().unwrap();
        assert_eq!(
            check_password_command,
            &CheckPasswordCommand {
                db_password_opt: Some("bonkers".to_string()),
            }
        );
    }

    #[test]
    fn complains_about_check_password_command_with_bad_syntax() {
        let subject = CommandFactoryReal::new();

        let result = subject.make(&[
            "check-password".to_string(),
            "bonkers".to_string(),
            "invalid".to_string(),
        ]);

        match result {
            Err(CommandFactoryError::CommandSyntax(msg)) => {
                // Note: when run with MASQ/Node/ci/all.sh, msg contains escape sequences for color.
                assert_eq!(
                    msg.contains("which wasn't expected, or isn't valid in this context"),
                    true,
                    "{}",
                    msg
                )
            }
            x => panic!("Expected CommandSyntax error, got {:?}", x),
        }
    }

    #[test]
    fn connection_status_command_works() {
        let subject = CommandFactoryReal::new();

        let command = subject.make(&["connection-status".to_string()]).unwrap();

        let connnection_status_command = command
            .as_any()
            .downcast_ref::<ConnectionStatusCommand>()
            .unwrap();
        assert_eq!(connnection_status_command, &ConnectionStatusCommand {});
    }

    #[test]
    fn factory_produces_set_password() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(&["set-password".to_string(), "abracadabra".to_string()])
            .unwrap();

        assert_eq!(
            command
                .as_any()
                .downcast_ref::<ChangePasswordCommand>()
                .unwrap(),
            &ChangePasswordCommand {
                old_password: None,
                new_password: "abracadabra".to_string()
            }
        );
    }

    #[test]
    fn factory_produces_set_configuration() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(&[
                "set-configuration".to_string(),
                "--gas-price".to_string(),
                "20".to_string(),
            ])
            .unwrap();

        assert_eq!(
            command
                .as_any()
                .downcast_ref::<SetConfigurationCommand>()
                .unwrap(),
            &SetConfigurationCommand {
                name: "gas-price".to_string(),
                value: "20".to_string(),
            }
        );
    }

    #[test]
    fn factory_produces_exit_location() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(&[
                "exit-location".to_string(),
                "--country-codes".to_string(),
                "CZ".to_string(),
            ])
            .unwrap();

        assert_eq!(
            command
                .as_any()
                .downcast_ref::<SetExitLocationCommand>()
                .unwrap(),
            &SetExitLocationCommand {
                exit_locations: vec![CountryCodes {
                    country_codes: vec!["CZ".to_string()],
                    priority: 1
                }],
                fallback_routing: false,
            }
        );
    }

    #[test]
    fn complains_about_set_configuration_command_with_no_parameters() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&["set-configuration".to_string()])
            .err()
            .unwrap();

        let msg = match result {
            CommandSyntax(msg) => msg,
            x => panic!("Expected syntax error, got {:?}", x),
        };
        assert!(
            msg.contains("The following required arguments were not provided:"),
            "{}",
            msg
        );
    }

    #[test]
    fn complains_about_setup_command_with_bad_syntax() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&["setup".to_string(), "--booga".to_string()])
            .err()
            .unwrap();

        let msg = match result {
            CommandSyntax(msg) => msg,
            x => panic!("Expected syntax error, got {:?}", x),
        };
        assert_eq!(msg.contains("Found argument '"), true, "{}", msg);
        assert_eq!(msg.contains("--booga"), true, "{}", msg);
        assert_eq!(
            msg.contains("which wasn't expected, or isn't valid in this context"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn complains_about_configuration_command_with_bad_syntax() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "configuration".to_string(),
                "--invalid".to_string(),
                "booga".to_string(),
            ])
            .err()
            .unwrap();

        let msg = match result {
            CommandSyntax(msg) => msg,
            x => panic!("Expected syntax error, got {:?}", x),
        };
        assert_eq!(msg.contains("Found argument"), true, "{}", msg);
        assert_eq!(msg.contains("--invalid"), true, "{}", msg);
        assert_eq!(
            msg.contains("which wasn't expected, or isn't valid in this context"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn factory_produces_connection_status() {
        let subject = CommandFactoryReal::new();

        let command = subject.make(&["connection-status".to_string()]).unwrap();

        assert_eq!(
            command
                .as_any()
                .downcast_ref::<ConnectionStatusCommand>()
                .unwrap(),
            &ConnectionStatusCommand {}
        );
    }

    #[test]
    fn complains_about_generate_wallets_command_with_bad_syntax() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "generate-wallets".to_string(),
                "--invalid".to_string(),
                "password".to_string(),
            ])
            .err()
            .unwrap();

        let msg = match result {
            CommandSyntax(msg) => msg,
            x => panic!("Expected syntax error, got {:?}", x),
        };
        assert_eq!(msg.contains("Found argument"), true, "{}", msg);
        assert_eq!(msg.contains("--invalid"), true, "{}", msg);
        assert_eq!(
            msg.contains("which wasn't expected, or isn't valid in this context"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn complains_about_financials_command_with_bad_syntax() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "financials".to_string(),
                "--make-me-rich".to_string(),
                "slowly".to_string(),
            ])
            .err()
            .unwrap();

        let msg = match result {
            CommandSyntax(msg) => msg,
            x => panic!("Expected syntax error, got {:?}", x),
        };
        assert_eq!(msg.contains("Found argument"), true, "{}", msg);
        assert_eq!(msg.contains("--make-me-rich"), true, "{}", msg);
        assert_eq!(
            msg.contains("which wasn't expected, or isn't valid in this context"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn testing_command_factory_with_good_command() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&["wallet-addresses".to_string(), "bonkers".to_string()])
            .unwrap();

        let wallet_address_command: &WalletAddressesCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            wallet_address_command,
            &WalletAddressesCommand {
                db_password: "bonkers".to_string(),
            }
        );
    }

    #[test]
    fn testing_command_factory_with_bad_command() {
        let subject = CommandFactoryReal::new();

        let result = subject.make(&["wallet-addresses".to_string()]);

        match result {
            Err(CommandFactoryError::CommandSyntax(msg)) => {
                // Note: when run with MASQ/Node/ci/all.sh, msg contains escape sequences for color.
                assert_eq!(
                    msg.contains("The following required arguments were not provided:"),
                    true,
                    "{}",
                    msg
                )
            }
            x => panic!("Expected CommandSyntax error, got {:?}", x),
        }
    }
}
