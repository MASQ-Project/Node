// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::schema::app;
use clap::ArgMatches;
use masq_lib::shared_schema::InsecurePort;

pub trait NonInteractiveClapFactory {
    fn make(&self) -> Box<dyn NonInteractiveClap>;
}

pub struct NonInteractiveClapFactoryReal;

// Tested by integration tests
impl NonInteractiveClapFactory for NonInteractiveClapFactoryReal {
    fn make(&self) -> Box<dyn NonInteractiveClap> {
        Box::new(NonInteractiveClapReal)
    }
}

pub trait NonInteractiveClap {
    fn non_interactive_initial_clap_operations(&self, args: &[String]) -> u16;
}

pub struct NonInteractiveClapReal;

// Partly tested by integration tests
impl NonInteractiveClap for NonInteractiveClapReal {
    fn non_interactive_initial_clap_operations(&self, args: &[String]) -> u16 {
        let matches = app().get_matches_from(args);
        matches
            .get_one::<InsecurePort>("ui-port")
            .expect("ui-port is not properly defaulted")
            .port
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::constants::DEFAULT_UI_PORT;

    #[test]
    fn non_interactive_clap_real_produces_default_value_for_ui_port() {
        let result = NonInteractiveClapReal.non_interactive_initial_clap_operations(
            &vec!["masq", "setup", "--chain"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
        );

        assert_eq!(result, DEFAULT_UI_PORT)
    }

    #[test]
    fn non_interactive_clap_real_accept_custom_value_for_ui_port() {
        let result = NonInteractiveClapReal.non_interactive_initial_clap_operations(
            &vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
        );

        assert_eq!(result, 10000)
    }
}
