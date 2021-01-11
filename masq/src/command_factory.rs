// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::check_password_command::CheckPasswordCommand;
use crate::commands::commands_common::Command;
use crate::commands::crash_command::CrashCommand;
use crate::commands::descriptor_command::DescriptorCommand;
use crate::commands::generate_wallets_command::GenerateWalletsCommand;
use crate::commands::setup_command::SetupCommand;
use crate::commands::shutdown_command::ShutdownCommand;
use crate::commands::start_command::StartCommand;

#[derive(Debug, PartialEq)]
pub enum CommandFactoryError {
    UnrecognizedSubcommand(String),
    CommandSyntax(String),
}

pub trait CommandFactory {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError>;
}

#[derive(Default)]
pub struct CommandFactoryReal {}

impl CommandFactory for CommandFactoryReal {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError> {
        let boxed_command: Box<dyn Command> = match pieces[0].as_str() {
            "change-password" => match ChangePasswordCommand::new_change(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "check-password" => match CheckPasswordCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "crash" => match CrashCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "descriptor" => Box::new(DescriptorCommand::new()),
            "generate-wallets" => match GenerateWalletsCommand::new(pieces) {
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

    #[test]
    fn complains_about_unrecognized_subcommand() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec!["booga".to_string(), "agoob".to_string()])
            .err()
            .unwrap();

        assert_eq!(result, UnrecognizedSubcommand("booga".to_string()));
    }

    #[test]
    fn factory_produces_change_password() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(vec![
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
            .make(vec![
                "change-password".to_string(),
                "abracadabra".to_string(),
            ])
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
            .make(vec!["check-password".to_string(), "bonkers".to_string()])
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

        let result = subject.make(vec![
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
    fn complains_about_generate_wallets_command_with_bad_syntax() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
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
    fn factory_produces_set_password() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(vec!["set-password".to_string(), "abracadabra".to_string()])
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
    fn complains_about_setup_command_with_bad_syntax() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec!["setup".to_string(), "--booga".to_string()])
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
}
