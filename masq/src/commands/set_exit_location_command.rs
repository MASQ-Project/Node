use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::as_any_ref_in_trait_impl;
use masq_lib::messages::{CountryCodes, UiSetExitLocationRequest, UiSetExitLocationResponse};
use masq_lib::shared_schema::common_validators;
use masq_lib::utils::ExpectValue;

#[derive(Debug, PartialEq, Eq)]
pub struct SetExitLocationCommand {
    pub exit_locations: Vec<CountryCodes>,
    pub fallback_routing: bool,
}

impl SetExitLocationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        match set_exit_location_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => {
                let exit_locations = match matches.is_present("country-codes") {
                    true => matches
                        .value_of("country-codes")
                        .expectv("required param")
                        .split("|")
                        .enumerate()
                        .map(|(index, code)| CountryCodes::from((code.to_string(), index)))
                        .collect(),
                    false => vec![],
                };
                let fallback_routing = match (
                    matches.is_present("fallback-routing"),
                    matches.is_present("country-codes"),
                ) {
                    (false, true) => false,
                    _ => true,
                };
                Ok(SetExitLocationCommand {
                    exit_locations,
                    fallback_routing,
                })
            }

            Err(e) => Err(format!("SetExitLocationCommand {}", e)),
        }
    }
}

impl Command for SetExitLocationCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiSetExitLocationRequest {
            exit_locations: self.exit_locations.clone(),
            fallback_routing: self.fallback_routing.clone(),
        };

        let _: UiSetExitLocationResponse =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS)?;
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}

const EXIT_LOCATION_ABOUT: &str =
    "If you activate exit-location preferences, all exit Nodes in countries you don't specify will be prohibited: \n\
    that is, if there is no exit Node available in any of your preferred countries, you'll get an error. However, \
    if you just want to make a suggestion, and you don't mind Nodes in other countries being used if nothing is available \
    in your preferred countries, you can specify --fallback-routing, and you'll get no error unless there are no exit Nodes \
    available anywhere.\n\n\
    Here are some example commands:\n\
        masq> exit-location                                                       // disable exit-location \n\
        masq> exit-location --fallback-routing                                    // disable exit-location \n\n\
        masq> exit-location --country-codes \"CZ,PL|SK\" --fallback-routing       // fallback-routing is ON, \"CZ\" and \"PL\" countries has same priority \"1\", \"SK\" has prirority \"2\"\n\
        masq> exit-location --country-codes \"CZ|SK\"                             // fallback-routing is OFF, \"CZ\" and \"SK\" countries has different prirority\n";

// TODO update following help when GH-469 is done
const COUNTRY_CODES_HELP: &str = "Establish a set of countries that your Node should try to use for exit Nodes. You should choose from the countries that host the \
        Nodes in your Neighborhood. List the countries in order of preference, separated by vertical pipes (|). If your level of preference \
        for a group of countries is the same, separate those countries by commas (,).\n\
        To obtain codes you cant use 'country-codes-list' command. You can specify country codes followingly:\n\n\
        masq> exit-location --country-codes \"CZ,PL|SK\"                          // \"CZ\" and \"PL\" countries has same priority \"1\", \"SK\" has prirority \"2\" \n\
        masq> exit-location --country-codes \"CZ|SK\"                             // \"CZ\" and \"SK\" countries has different prirority\n";

const FALLBACK_ROUTING_HELP: &str = "If you just want to make a suggestion, and you don't mind Nodes in other countries being used if nothing is available \
     in your preferred countries, you can specify --fallback-routing, and you'll get no error unless there are no exit Nodes \
     available anywhere. \n Here are some examples: \n\n\
     masq> exit-location --country-codes \"CZ\" --fallback-routing              // Set exit-location for \"CZ\" country with fallback-routing on \n\
     masq> exit-location --country-codes \"CZ\"                                 // Set exit-location for \"CZ\" country with fallback-routing off \n";

pub fn set_exit_location_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("exit-location")
        .about(EXIT_LOCATION_ABOUT)
        .arg(
            Arg::with_name("country-codes")
                .long("country-codes")
                .value_name("COUNTRY-CODES")
                .validator(common_validators::validate_exit_locations)
                .help(COUNTRY_CODES_HELP)
                .required(false),
        )
        .arg(
            Arg::with_name("fallback-routing")
                .long("fallback-routing")
                .value_name("FALLBACK-ROUTING")
                .help(FALLBACK_ROUTING_HELP)
                .takes_value(false)
                .required(false),
        )
}

#[cfg(test)]
pub mod tests {
    use crate::commands::commands_common::{Command, STANDARD_COMMAND_TIMEOUT_MILLIS};
    use crate::commands::set_exit_location_command::SetExitLocationCommand;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{
        CountryCodes, ToMessageBody, UiSetExitLocationRequest, UiSetExitLocationResponse,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn can_deserialize_ui_set_exit_location() {
        let expected_request = UiSetExitLocationRequest {
            fallback_routing: true,
            exit_locations: vec![
                CountryCodes {
                    country_codes: vec!["CZ".to_string(), "SK".to_string()],
                    priority: 1,
                },
                CountryCodes {
                    country_codes: vec!["AT".to_string(), "DE".to_string()],
                    priority: 2,
                },
                CountryCodes {
                    country_codes: vec!["PL".to_string()],
                    priority: 3,
                },
            ],
        };
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {}.tmb(0)));
        let stderr_arc = context.stderr_arc();
        let subject = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--country-codes".to_string(),
            "CZ,SK|AT,DE|PL".to_string(),
            "--fallback-routing".to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        let expected_message_body = expected_request.tmb(0);
        assert_eq!(
            transact_params.as_slice(),
            &[(expected_message_body, STANDARD_COMMAND_TIMEOUT_MILLIS)]
        );
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
    }

    #[test]
    fn providing_no_fallback_cause_exit_location_blocking_routing_request() {
        let expected_request = UiSetExitLocationRequest {
            fallback_routing: false,
            exit_locations: vec![CountryCodes {
                country_codes: vec!["CZ".to_string()],
                priority: 1,
            }],
        };
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {}.tmb(0)));
        let stderr_arc = context.stderr_arc();
        let subject = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--country-codes".to_string(),
            "CZ".to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        let expected_message_body = expected_request.tmb(0);
        assert_eq!(
            transact_params.as_slice(),
            &[(expected_message_body, STANDARD_COMMAND_TIMEOUT_MILLIS)]
        );
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
    }

    #[test]
    fn providing_no_arguments_cause_exit_location_reset_request() {
        let expected_request = UiSetExitLocationRequest {
            fallback_routing: true,
            exit_locations: vec![],
        };
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {}.tmb(0)));
        let stderr_arc = context.stderr_arc();
        let subject = SetExitLocationCommand::new(&["exit-location".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        let expected_message_body = expected_request.tmb(0);
        assert_eq!(
            transact_params.as_slice(),
            &[(expected_message_body, STANDARD_COMMAND_TIMEOUT_MILLIS)]
        );
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
    }
}
