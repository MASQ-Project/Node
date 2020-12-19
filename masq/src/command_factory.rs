// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use crate::commands::check_password_command::CheckPasswordCommand;
use crate::commands::change_password_command::ChangePasswordCommand;
use crate::commands::commands_common::Command;
use crate::commands::crash_command::CrashCommand;
use crate::commands::descriptor_command::DescriptorCommand;
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
            "check-password" => match CheckPasswordCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => unimplemented!("{}", msg),
            },
            "change-password" => match ChangePasswordCommand::new(pieces){
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "crash" => match CrashCommand::new(pieces) {
                Ok(command) => Box::new(command),
                Err(msg) => return Err(CommandSyntax(msg)),
            },
            "descriptor" => Box::new(DescriptorCommand::new()),
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
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{UiChangePasswordResponse, ToMessageBody};

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

    #[test]
    fn make_handles_error_when_the_second_parameter_of_change_password_is_not_supplied() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Ok(UiChangePasswordResponse {}.tmb(1230)));

        let result:Result<(),CommandFactoryError> = if let Err(e) = factory
            .make(vec!["change-password"
                           .to_string(), "abracadabra"
                           .to_string()])
        {Err(e)} else {Err((CommandFactoryError::UnrecognizedSubcommand("testing".to_string())))};

        assert_eq!(result, Err(CommandFactoryError::CommandSyntax(String::from("error: The following required arguments were not provided:\n    <new-db-password>\n\nUSAGE:\n    change-password <old-db-password> <new-db-password>\n\nFor more information try --help\n"))));
    }

    // Rust isn't a reflective enough language to allow easy test-driving of the make() method
    // here. Instead, we're driving the successful paths in commands_common by making real commands
    // and executing them.
}
