use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{CountryCodes, UiSetExitLocationRequest, UiSetExitLocationResponse};
use masq_lib::shared_schema::common_validators;
use masq_lib::utils::ExpectValue;
use masq_lib::{as_any_ref_in_trait_impl, short_writeln};

#[derive(Debug, PartialEq, Eq)]
pub struct SetExitLocationCommand {
    pub exit_locations: Vec<CountryCodes>,
    pub fallback_routing: bool,
}

impl SetExitLocationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        match set_exit_location_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => {
                let exit_locations = matches
                    .value_of("country-codes")
                    .expectv("required param")
                    .split("|") //TODO check it is required in clap
                    .enumerate()
                    .map(|(index, code)| CountryCodes::from((code.to_string(), index)))
                    .collect();
                let fallback_routing = match matches.value_of("fallback-routing") {
                    Some(_) => true,
                    None => false,
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
        short_writeln!(context.stdout(), "Parameter was successfully set");
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}

const EXIT_LOACTION_ABOUT: &str = "TODO finish me! Sets Exit Location for Exit Node.";

const COUNTRY_CODES_HELP: &str = "TODO finish me!";

pub fn set_exit_location_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("exit-location")
        .about(EXIT_LOACTION_ABOUT)
        .arg(
            Arg::with_name("country-codes")
                .long("country-codes")
                .value_name("COUNTRY-CODES")
                .validator(common_validators::validate_exit_location_pairs)
                .help(COUNTRY_CODES_HELP)
                .required(true)
        )
        .arg(
            Arg::with_name("fallback-routing")
                .help("Set whether you want to fallback on non-blocking routing for desired Exit Location.")
                .long("fallback-routing")
                .value_name("FALLBACK-ROUTING")
                .default_value("true")
                .required(false)
        )
}

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
                    country_codes: vec!["PL".to_string(), "HU".to_string()],
                    priority: 3,
                },
            ],
        };
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {}.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = SetExitLocationCommand::new(&[
            "exit-location".to_string(),
            "--country-codes".to_string(),
            "CZ,SK|AT,DE|PL,HU".to_string(),
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
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(&stdout.get_string(), "Parameter was successfully set\n");
    }
}
