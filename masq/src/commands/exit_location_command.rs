// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, ArgGroup, SubCommand};
use masq_lib::constants::EXIT_COUNTRY_MISSING_COUNTRIES_ERROR;
use masq_lib::exit_locations::ExitLocationSet;
use masq_lib::messages::{CountryGroups, UiSetExitLocationRequest, UiSetExitLocationResponse};
use masq_lib::shared_schema::common_validators;
use masq_lib::{as_any_ref_in_trait_impl, short_writeln};
use std::fmt::Debug;

const EXIT_LOCATION_ABOUT: &str =
    "If you activate exit-location preferences, all exit Nodes in countries you don't specify will be prohibited: \n\
    that is, if there is no exit Node available in any of your preferred countries, you'll get an error. However, \
    if you just want to make a suggestion, and you don't mind Nodes in other countries being used if nothing is available \
    in your preferred countries, you can specify --fallback-routing, and you'll get no error unless there are no exit Nodes \
    available anywhere.\n\n\
    Here are some example commands:\n\
        masq> exit-location --show-countries    // show all country codes available for exit in Database\n\
        masq> exit-location                     // disable exit-location preferences\n\
        masq> exit-location --fallback-routing  // disable exit-location preferences\n\
        masq> exit-location --country-codes \"CZ,PL|SK\" --fallback-routing \n\t// fallback-routing is ON, \"CZ\" and \"PL\" countries have same priority \"1\", \"SK\" has priority \"2\"\n\
        masq> exit-location --country-codes \"CZ|SK\"       \n\t// fallback-routing is OFF, \"CZ\" and \"SK\" countries have different priority\n";

const COUNTRY_CODES_HELP: &str = "Establish a set of countries that your Node should try to use for exit Nodes. You should choose from the countries that host the \
        Nodes in your Neighborhood. List the countries in order of preference, separated by vertical pipes (|). If your level of preference \
        for a group of countries is the same, separate those countries by commas (,).\n\
        You can specify country codes as follows:\n\n\
        masq> exit-location --country-codes \"CZ,PL|SK\"        \n\t// \"CZ\" and \"PL\" countries have same priority \"1\", \"SK\" has priority \"2\" \n\
        masq> exit-location --country-codes \"CZ|SK\"           \n\t// \"CZ\" and \"SK\" countries have different priority\n\n";

const FALLBACK_ROUTING_HELP: &str = "If you just want to make a suggestion, and you don't mind Nodes in other countries being used if nothing is available \
     in your preferred countries, you can specify --fallback-routing, and you'll get no error unless there are no exit Nodes \
     available anywhere. \n Here are some examples: \n\n\
     masq> exit-location --country-codes \"CZ\" --fallback-routing  \n\t// Set exit-location for \"CZ\" country with fallback-routing on \n\
     masq> exit-location --country-codes \"CZ\"                     \n\t// Set exit-location for \"CZ\" country with fallback-routing off \n\n";

const SHOW_COUNTRIES_HELP: &str = "Use this flag to display all country codes available for exit Nodes in your Neighborhood:  \n\n\
    masq> exit-location --show-countries ";

pub fn exit_location_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("exit-location").about(EXIT_LOCATION_ABOUT)
}

#[derive(Debug, PartialEq, Eq)]
pub struct SetExitLocationCommand {
    pub exit_locations: Vec<CountryGroups>,
    pub fallback_routing: bool,
    pub show_countries: bool,
}

impl SetExitLocationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        match set_exit_location_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => {
                let exit_locations = match matches.is_present("country-codes") {
                    true => matches
                        .values_of("country-codes")
                        .expect("Expected Country Codes")
                        .into_iter()
                        .enumerate()
                        .map(|(index, code)| CountryGroups::from((code.to_string(), index)))
                        .collect(),
                    false => vec![],
                };
                let fallback_routing = !matches!(
                    (
                        matches.is_present("fallback-routing"),
                        matches.is_present("country-codes")
                    ),
                    (false, true)
                );
                let show_countries = matches.is_present("show-countries");
                Ok(SetExitLocationCommand {
                    exit_locations,
                    fallback_routing,
                    show_countries,
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
            fallback_routing: self.fallback_routing,
            show_countries: self.show_countries,
        };
        let output: Result<UiSetExitLocationResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(exit_location_response) => {
                if let Some(exit_countries) = exit_location_response.exit_countries {
                    match !exit_countries.is_empty() {
                        true => short_writeln!(
                            context.stdout(),
                            "Countries available for exit-location: {:?}",
                            exit_countries
                        ),
                        false => short_writeln!(
                            context.stderr(),
                            "No countries available for exit-location!"
                        ),
                    }
                } else {
                    match exit_location_response.fallback_routing {
                        true => short_writeln!(context.stdout(), "Fallback Routing is set.",),
                        false => short_writeln!(context.stdout(), "Fallback Routing NOT set.",),
                    }
                }
                if !exit_location_response.exit_country_selection.is_empty() {
                    let location_set = ExitLocationSet {
                        locations: exit_location_response.exit_country_selection,
                    };
                    if !exit_location_response.missing_countries.is_empty() {
                        short_writeln!(
                            context.stdout(),
                            "Following countries are missing in Database: {:?}",
                            exit_location_response.missing_countries
                        );
                        short_writeln!(
                            context.stderr(),
                            "code: {}\nmessage: {:?}",
                            EXIT_COUNTRY_MISSING_COUNTRIES_ERROR,
                            exit_location_response.missing_countries
                        );
                    }
                    short_writeln!(context.stdout(), "Exit location set: {}", location_set);
                } else if exit_location_response.fallback_routing
                    && exit_location_response.exit_country_selection.is_empty()
                {
                    short_writeln!(context.stdout(), "Exit location is Unset.");
                }
                Ok(())
            }
            Err(Payload(code, message)) => {
                short_writeln!(context.stderr(), "code: {}\nmessage: {}", code, message);
                if code == EXIT_COUNTRY_MISSING_COUNTRIES_ERROR {
                    short_writeln!(
                        context.stdout(),
                        "All requested countries are missing in Database: {}",
                        message
                    );
                }
                Err(Payload(code, message))
            }
            Err(err) => {
                short_writeln!(context.stderr(), "Error: {}", err);
                Err(err)
            }
        }
    }

    as_any_ref_in_trait_impl!();
}

pub fn set_exit_location_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("exit-location")
        .about(EXIT_LOCATION_ABOUT)
        .arg(
            Arg::with_name("country-codes")
                .long("country-codes")
                .value_name("COUNTRY-CODES")
                .value_delimiter("|")
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
        .arg(
            Arg::with_name("show-countries")
                .long("show-countries")
                .value_name("SHOW-COUNTRIES")
                .help(SHOW_COUNTRIES_HELP)
                .takes_value(false)
                .required(false),
        )
        .group(
            ArgGroup::with_name("show-countries-fallback")
                .args(&["show-countries", "fallback-routing"]),
        )
        .group(
            ArgGroup::with_name("show-countries-ccodes").args(&["show-countries", "country-codes"]),
        )
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::{
        Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
    };
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::constants::EXIT_COUNTRY_MISSING_COUNTRIES_ERROR;
    use masq_lib::messages::{
        CountryGroups, ExitLocation, ToMessageBody, UiSetExitLocationRequest,
        UiSetExitLocationResponse,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            EXIT_LOCATION_ABOUT,
            "If you activate exit-location preferences, all exit Nodes in countries you don't specify will be prohibited: \n\
            that is, if there is no exit Node available in any of your preferred countries, you'll get an error. However, \
            if you just want to make a suggestion, and you don't mind Nodes in other countries being used if nothing is available \
            in your preferred countries, you can specify --fallback-routing, and you'll get no error unless there are no exit Nodes \
            available anywhere.\n\n\
            Here are some example commands:\n\
                masq> exit-location --show-countries    // show all country codes available for exit in Database\n\
                masq> exit-location                     // disable exit-location preferences\n\
                masq> exit-location --fallback-routing  // disable exit-location preferences\n\
                masq> exit-location --country-codes \"CZ,PL|SK\" --fallback-routing \n\t// fallback-routing is ON, \"CZ\" and \"PL\" countries have same priority \"1\", \"SK\" has priority \"2\"\n\
                masq> exit-location --country-codes \"CZ|SK\"       \n\t// fallback-routing is OFF, \"CZ\" and \"SK\" countries have different priority\n"
        );
        assert_eq!(
            COUNTRY_CODES_HELP,
                "Establish a set of countries that your Node should try to use for exit Nodes. You should choose from the countries that host the \
            Nodes in your Neighborhood. List the countries in order of preference, separated by vertical pipes (|). If your level of preference \
            for a group of countries is the same, separate those countries by commas (,).\n\
            You can specify country codes as follows:\n\n\
            masq> exit-location --country-codes \"CZ,PL|SK\"        \n\t// \"CZ\" and \"PL\" countries have same priority \"1\", \"SK\" has priority \"2\" \n\
            masq> exit-location --country-codes \"CZ|SK\"           \n\t// \"CZ\" and \"SK\" countries have different priority\n\n"
        );
        assert_eq!(
            FALLBACK_ROUTING_HELP, "If you just want to make a suggestion, and you don't mind Nodes in other countries being used if nothing is available \
             in your preferred countries, you can specify --fallback-routing, and you'll get no error unless there are no exit Nodes \
             available anywhere. \n Here are some examples: \n\n\
             masq> exit-location --country-codes \"CZ\" --fallback-routing  \n\t// Set exit-location for \"CZ\" country with fallback-routing on \n\
             masq> exit-location --country-codes \"CZ\"                     \n\t// Set exit-location for \"CZ\" country with fallback-routing off \n\n"
        );
        assert_eq!(
            SHOW_COUNTRIES_HELP,
                    "Use this flag to display all country codes available for exit Nodes in your Neighborhood:  \n\n\
            masq> exit-location --show-countries "
        );
    }

    #[test]
    fn testing_missing_location_error() {
        let factory = CommandFactoryReal::new();
        let mut context =
            CommandContextMock::new().transact_result(Err(ContextError::PayloadError(
                EXIT_COUNTRY_MISSING_COUNTRIES_ERROR,
                "\"CZ, SK, IN\"".to_string(),
            )));
        let subject = factory.make(&["exit-location".to_string()]).unwrap();

        let result = subject.execute(&mut context);
        let stderr = context.stderr_arc();
        let stdout = context.stdout_arc();
        assert_eq!(
            stdout.lock().unwrap().get_string(),
            "All requested countries are missing in Database: \"CZ, SK, IN\"\n"
        );
        assert_eq!(
            stderr.lock().unwrap().get_string(),
            "code: 9223372036854775816\nmessage: \"CZ, SK, IN\"\n".to_string()
        );
        assert_eq!(
            result,
            Err(CommandError::Payload(
                9223372036854775816,
                "\"CZ, SK, IN\"".to_string()
            ))
        );
    }

    #[test]
    fn testing_handler_for_exit_location_responose() {
        let message_body = Ok(UiSetExitLocationResponse {
            fallback_routing: true,
            exit_country_selection: vec![],
            exit_countries: None,
            missing_countries: vec![],
        }
        .tmb(1234));

        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(message_body);
        let subject = factory
            .make(&[
                "exit-location".to_string(),
                "--fallback-routing".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);
        let stderr = context.stderr_arc();
        let stdout = context.stdout_arc();
        assert_eq!(
            stdout.lock().unwrap().get_string(),
            "Fallback Routing is set.\nExit location is Unset.\n".to_string()
        );
        assert_eq!(stderr.lock().unwrap().get_string(), "".to_string());
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn can_deserialize_ui_set_exit_location() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {
                fallback_routing: true,
                exit_country_selection: vec![
                    ExitLocation {
                        country_codes: vec!["CZ".to_string(), "SK".to_string()],
                        priority: 1,
                    },
                    ExitLocation {
                        country_codes: vec!["AT".to_string(), "DE".to_string()],
                        priority: 2,
                    },
                    ExitLocation {
                        country_codes: vec!["PL".to_string()],
                        priority: 3,
                    },
                ],
                exit_countries: None,
                missing_countries: vec![],
            }
            .tmb(0)));
        let stderr_arc = context.stderr_arc();
        let stdout_arc = context.stdout_arc();
        let subject = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--country-codes".to_string(),
            "CZ,SK|AT,DE|PL".to_string(),
            "--fallback-routing".to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let expected_request = UiSetExitLocationRequest {
            fallback_routing: true,
            exit_locations: vec![
                CountryGroups {
                    country_codes: vec!["CZ".to_string(), "SK".to_string()],
                    priority: 1,
                },
                CountryGroups {
                    country_codes: vec!["AT".to_string(), "DE".to_string()],
                    priority: 2,
                },
                CountryGroups {
                    country_codes: vec!["PL".to_string()],
                    priority: 3,
                },
            ],
            show_countries: false,
        };
        let transact_params = transact_params_arc.lock().unwrap();
        let expected_message_body = expected_request.tmb(0);
        assert_eq!(
            transact_params.as_slice(),
            &[(expected_message_body, STANDARD_COMMAND_TIMEOUT_MILLIS)]
        );
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(&stdout.get_string(), "Fallback Routing is set.\nExit location set: Country Codes: [\"CZ\", \"SK\"] - Priority: 1; Country Codes: [\"AT\", \"DE\"] - Priority: 2; Country Codes: [\"PL\"] - Priority: 3\n");
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
    }

    #[test]
    fn absence_of_fallback_routing_produces_fallback_routing_false() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {
                fallback_routing: false,
                exit_country_selection: vec![ExitLocation {
                    country_codes: vec!["CZ".to_string()],
                    priority: 1,
                }],
                exit_countries: None,
                missing_countries: vec![],
            }
            .tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--country-codes".to_string(),
            "CZ".to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let expected_request = UiSetExitLocationRequest {
            fallback_routing: false,
            exit_locations: vec![CountryGroups {
                country_codes: vec!["CZ".to_string()],
                priority: 1,
            }],
            show_countries: false,
        };
        let transact_params = transact_params_arc.lock().unwrap();
        let expected_message_body = expected_request.tmb(0);
        assert_eq!(
            transact_params.as_slice(),
            &[(expected_message_body, STANDARD_COMMAND_TIMEOUT_MILLIS)]
        );
        let stdout = stdout_arc.lock().unwrap();
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(
            &stdout.get_string(),
            "Fallback Routing NOT set.\nExit location set: Country Codes: [\"CZ\"] - Priority: 1\n"
        );
        assert_eq!(&stderr.get_string(), "");
    }

    #[test]
    fn providing_no_arguments_cause_exit_location_reset_request() {
        let result = SetExitLocationCommand::new(&["exit-location".to_string()]).unwrap();

        assert_eq!(
            result,
            SetExitLocationCommand {
                exit_locations: vec![],
                fallback_routing: true,
                show_countries: false
            }
        );
    }

    #[test]
    fn providing_show_countries_flag_causes_request_for_list_of_countries() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {
                fallback_routing: false,
                exit_country_selection: vec![],
                exit_countries: Some(vec!["CZ".to_string()]),
                missing_countries: vec![],
            }
            .tmb(0)));
        let stderr_arc = context.stderr_arc();
        let stdout_arc = context.stdout_arc();
        let subject = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--show-countries".to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let expected_request = UiSetExitLocationRequest {
            fallback_routing: true,
            exit_locations: vec![],
            show_countries: true,
        };
        let transact_params = transact_params_arc.lock().unwrap();
        let expected_message_body = expected_request.tmb(0);
        assert_eq!(
            transact_params.as_slice(),
            &[(expected_message_body, STANDARD_COMMAND_TIMEOUT_MILLIS)]
        );
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(
            &stdout.get_string(),
            "Countries available for exit-location: [\"CZ\"]\n"
        );
    }

    #[test]
    fn providing_show_countries_with_country_codes_fails() {
        let result = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--show-countries".to_string(),
            "--country-codes".to_string(),
            "CZ".to_string(),
        ])
        .unwrap_err();

        let result_expected =
            "cannot be used with one or more of the other specified arguments\n\nUSAGE:\n";
        let expected_one = "show-countries";
        let expected_two = "country-codes";
        assert!(
            result.contains(result_expected),
            "result was {:?}, but expected {:?}",
            result,
            result_expected,
        );
        assert!(
            result.contains(expected_one) || result.contains(expected_two),
            "result should have contained either {:?}, or {:?}, but was instead {:?}",
            expected_one,
            expected_two,
            result
        );
    }

    #[test]
    fn providing_show_countries_with_fallback_routing_fails() {
        let result = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--show-countries".to_string(),
            "--fallback-routing".to_string(),
        ])
        .unwrap_err();

        let result_expected =
            "cannot be used with one or more of the other specified arguments\n\nUSAGE:\n";
        let expected_one = "show-countries";
        let expected_two = "fallback-routing";
        assert!(
            result.contains(result_expected),
            "result was {:?}, but expected {:?}",
            result,
            result_expected,
        );
        assert!(
            result.contains(expected_one) || result.contains(expected_two),
            "result should have contained either {:?}, or {:?}, but was instead {:?}",
            expected_one,
            expected_two,
            result
        );
    }
}
