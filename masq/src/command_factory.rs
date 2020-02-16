// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactoryError::UnrecognizedSubcommand;
use crate::commands::{Command, SetupCommand, ShutdownCommand, StartCommand};

#[derive(Debug, PartialEq)]
pub enum CommandFactoryError {
    UnrecognizedSubcommand(String),
}

pub trait CommandFactory {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError>;
}

#[derive(Default)]
pub struct CommandFactoryReal {}

impl CommandFactory for CommandFactoryReal {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError> {
        let command: Box<dyn Command> = match pieces[0].as_str() {
            "setup" => Box::new(SetupCommand::new(pieces)),
            "start" => Box::new(StartCommand::new()),
            "shutdown" => Box::new(ShutdownCommand::new()),
            unrecognized => return Err(UnrecognizedSubcommand(unrecognized.to_string())),
        };
        Ok(command)
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

    // Rust isn't a reflective enough language to allow easy test-driving of the make() method
    // here. Instead, we're driving the successful paths in commands.rs by making real commands
    // and executing them.
}
