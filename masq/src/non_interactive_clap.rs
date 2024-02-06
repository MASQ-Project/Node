// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::schema::app;
use clap::{value_t, ArgMatches};

#[allow(clippy::upper_case_acronyms)]
pub trait NIClapFactory {
    fn make(&self) -> Box<dyn NonInteractiveClap>;
}

#[allow(clippy::upper_case_acronyms)]
pub struct NIClapFactoryReal;

//tested by integration tests
impl NIClapFactory for NIClapFactoryReal {
    fn make(&self) -> Box<dyn NonInteractiveClap> {
        Box::new(NonInteractiveClapReal)
    }
}

pub trait NonInteractiveClap {
    fn non_interactive_initial_clap_operations(&self, args: &[String]) -> u16;
}

pub struct NonInteractiveClapReal;

//partly tested by integration tests
impl NonInteractiveClap for NonInteractiveClapReal {
    fn non_interactive_initial_clap_operations(&self, args: &[String]) -> u16 {
        let matches = handle_help_or_version_if_required(args);
        value_t!(matches, "ui-port", u16).expect("ui-port is not properly defaulted")
    }
}

fn handle_help_or_version_if_required<'a>(args: &[String]) -> ArgMatches<'a> {
    app().get_matches_from(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::utils::to_string;

    #[test]
    fn non_interactive_clap_real_produces_default_value_for_ui_port() {
        let result = NonInteractiveClapReal.non_interactive_initial_clap_operations(
            &vec!["masq", "setup", "--chain"]
                .iter()
                .map(to_string)
                .collect::<Vec<String>>(),
        );

        assert_eq!(result, DEFAULT_UI_PORT)
    }

    #[test]
    fn non_interactive_clap_real_accept_custom_value_for_ui_port() {
        let result = NonInteractiveClapReal.non_interactive_initial_clap_operations(
            &vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
                .iter()
                .map(to_string)
                .collect::<Vec<String>>(),
        );

        assert_eq!(result, 10000)
    }
}
