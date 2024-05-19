// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::schema::app;
use clap::error::ErrorKind;
use masq_lib::shared_schema::InsecurePort;

pub trait NonInteractiveClapFactory: Send{
    fn make(&self) -> Box<dyn NonInteractiveClap>;
}

pub struct NonInteractiveClapFactoryReal;

impl NonInteractiveClapFactory for NonInteractiveClapFactoryReal {
    fn make(&self) -> Box<dyn NonInteractiveClap> {
        Box::new(NonInteractiveClapReal)
    }
}

pub trait NonInteractiveClap {
    fn parse_initialization_args(&self, args: &[String]) -> InitializationArgs;
}

pub struct NonInteractiveClapReal;

impl NonInteractiveClap for NonInteractiveClapReal {
    fn parse_initialization_args(&self, args: &[String]) -> InitializationArgs {
        let matches = match app().try_get_matches_from(args) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::DisplayHelp => {
                todo!()
            }
            Err(e) if e.kind() == ErrorKind::DisplayVersion => {
                todo!()
            }
            Err(e) => todo!(),
        };
        let ui_port = matches
            .get_one::<InsecurePort>("ui-port")
            .expect("ui-port is not properly defaulted")
            .port;
        InitializationArgs::new(ui_port)
    }
}

pub struct InitializationArgs {
    pub ui_port: u16,
}

impl InitializationArgs {
    pub fn new(ui_port: u16) -> Self {
        Self { ui_port }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::constants::DEFAULT_UI_PORT;

    #[test]
    fn non_interactive_clap_real_produces_default_values() {
        let result = NonInteractiveClapReal.parse_initialization_args(
            &vec!["masq", "setup", "--chain"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
        );

        assert_eq!(result.ui_port, DEFAULT_UI_PORT)
    }

    #[test]
    fn non_interactive_clap_real_produces_custom_values() {
        let result = NonInteractiveClapReal.parse_initialization_args(
            &vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
        );

        assert_eq!(result.ui_port, 10000)
    }
}
