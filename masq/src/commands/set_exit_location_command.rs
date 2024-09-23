use clap::{App, Arg, SubCommand};
use masq_lib::{as_any_ref_in_trait_impl, short_writeln};
use masq_lib::messages::{CountryCodes, UiSetExitLocationRequest, UiSetExitLocationResponse};
use masq_lib::shared_schema::{common_validators, exit_location_arg, EXIT_LOCATION_HELP};
use masq_lib::utils::ExpectValue;
use crate::command_context::CommandContext;
use crate::commands::commands_common::{Command, CommandError, transaction};
use crate::commands::set_configuration_command::{set_configuration_subcommand, set_configurationify};

const EXIT_LOCATION_ABOUT: &str = "Set exit location";

#[derive(Debug, PartialEq, Eq)]
pub struct SetExitLocationCommand {
    pub exit_locations: Vec<CountryCodes>,
    pub fallback_routing: bool
}

pub fn exit_locationify<'a>(shared_schema_arg: Arg<'a, 'a>) -> Arg<'a, 'a> {
    shared_schema_arg.takes_value(true).min_values(0)
}

impl SetExitLocationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let country_codes_opt = pieces.get(1).map(|s| &s[2..]);
        let fallback_routing_opt = pieces.get(3).map(|s| &s[0..]);
        match set_exit_location_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => {
                let country_codes = country_codes_opt.expectv("required param");
                Ok(SetExitLocationCommand {
                    exit_locations: matches.value_of(country_codes).expectv("required param").split("|")
                        .enumerate()
                        .map(|(index, code)| CountryCodes::from((code.to_string(), index)))
                        .collect(),
                    fallback_routing: match fallback_routing_opt { Some(_) => true, None => false },
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

        let command: UiSetExitLocationResponse = transaction(input, context, 1000)?;
        println!("command: {:#?}", command);
        short_writeln!(context.stdout(), "Parameter was successfully set");
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}

const EXIT_LOACTION_ABOUT: &str =
    "TODO finish me! Sets Exit Location for Exit Node.";

const COUNTRY_CODES_HELP: &str =
    "TODO finish me!";

pub fn set_exit_location_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("exit-location")
        .about(EXIT_LOACTION_ABOUT)
        .arg(
            Arg::with_name("country-codes")
                .long("country-codes")
                .value_name("COUNTRY-CODES")
                .validator(common_validators::validate_exit_location_pairs)
                .help(COUNTRY_CODES_HELP)
        )
        .arg(
            Arg::with_name("fallback-routing")
                .help("Set whether you want to fallback on non-blocking routing for desired Exit Location.")
                .long("fallback-routing")
                .value_name("FALLBACK-ROUTING")
                .default_value("false")
                .required(true)
        )
}

pub mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use masq_lib::messages::{ToMessageBody, UiSetExitLocationResponse};
    use crate::commands::commands_common::{Command};
    use crate::commands::set_exit_location_command::SetExitLocationCommand;
    use crate::test_utils::mocks::CommandContextMock;

    #[test]
    fn can_deserialize_ui_set_exit_location() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetExitLocationResponse {}.tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = SetExitLocationCommand::new(&[
            "exit-locaiton".to_string(),
            "--country-codes".to_string(),
            "CZ,SK|AT|PL".to_string(),
            "--fallback-routing".to_string(),
        ])
            .unwrap();


        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        println!("*transact_params {:#?}", *transact_params);
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(&stdout.get_string(), "Parameter was successfully set\n");
    }
}

// let json = r#"
//     {
//         "fallback_routing: false,
//         "exit_locations": [
//             {
//                 "country_codes": ["CZ", "SK"],
//                 "priority": 1,
//             },
//             {
//                 "country_codes": ["DE", "AT"],
//                 "priority": 2,
//             }
//         ]
//     }
// "#
//     .to_string();
// let message_body = MessageBody {
//     opcode: "exit-locations".to_string(),
//     path: Conversation(0),
//     payload: Ok(json),
// };

// let output: Result<UiSetExitLocationResponse, CommandError> =
//     transaction(message_body, context, STANDARD_COMMAND_TIMEOUT_MILLIS);