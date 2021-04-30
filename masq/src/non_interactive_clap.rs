use crate::schema::app;
use clap::{value_t, ArgMatches};

pub trait NIClapFactory {
    fn make(&self) -> Box<dyn NonInteractiveClap>;
}

pub struct NonInteractiveClapFactoryReal;

//tested by integration tests
impl NIClapFactory for NonInteractiveClapFactoryReal {
    fn make(&self) -> Box<dyn NonInteractiveClap> {
        Box::new(NonInteractiveClapReal)
    }
}

pub trait NonInteractiveClap {
    fn non_interactive_clap_circuit(&self, args: &[String]) -> u16;
}

pub struct NonInteractiveClapReal;

//partly tested by integration tests
#[allow(unreachable_code)]
impl NonInteractiveClap for NonInteractiveClapReal {
    fn non_interactive_clap_circuit(&self, args: &[String]) -> u16 {
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

    #[test]
    fn non_interactive_clap_real_produces_default_value_for_ui_port() {
        let result = NonInteractiveClapReal.non_interactive_clap_circuit(
            &vec!["masq", "setup", "--chain"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
        );

        assert_eq!(result, DEFAULT_UI_PORT)
    }

    #[test]
    fn non_interactive_clap_real_accept_custom_value_for_ui_port() {
        let result = NonInteractiveClapReal.non_interactive_clap_circuit(
            &vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
                .iter()
                .map(|str| str.to_string())
                .collect::<Vec<String>>(),
        );

        assert_eq!(result, 10000)
    }
}
