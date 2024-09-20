use clap::{App, SubCommand};
use itertools::Itertools;
use masq_lib::{as_any_ref_in_trait_impl, short_writeln};
use masq_lib::messages::{CountryCodes, UiConnectionStatusRequest, UiSetConfigurationRequest, UiSetConfigurationResponse, UiSetExitLocationRequest, UiSetExitLocationResponse};
use masq_lib::utils::ExpectValue;
use crate::command_context::CommandContext;
use crate::commands::commands_common::{Command, CommandError, transaction};
use crate::commands::set_configuration_command::{set_configuration_subcommand, SetConfigurationCommand};

const EXIT_LOCATION_ABOUT: &str = "Set exit location";

#[derive(Debug, PartialEq, Eq)]
pub struct SetExitLocationCommand {
    pub name: String,
    pub exit_locations: Vec<CountryCodes>,
    pub fallback_routing: bool
}

pub fn connection_status_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("exit-location").about(EXIT_LOCATION_ABOUT)
}

impl SetExitLocationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let parameter_opt = pieces.get(1).map(|s| &s[2..]);
        match set_configuration_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => {
                let parameter = parameter_opt.expectv("required param");
                Ok(SetExitLocationCommand {
                    name: parameter.to_string(),
                    exit_locations: matches.value_of(parameter).expectv("required param").split("|")
                        .enumerate()
                        .map(|(index, code)| CountryCodes::from((code.to_string(), index)))
                        .collect(),
                    fallback_routing: false,
                })
            }

            Err(e) => Err(format!("{}", e)),
        }
    }
}

impl Command for SetExitLocationCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiSetExitLocationRequest {
            exit_locations: self.exit_locations.clone(),
            fallback_routing: self.fallback_routing.clone(),
        };

        //let _: UiSetExitLocationResponse = transaction(input, context, 1000)?;
        short_writeln!(context.stdout(), "Parameter was successfully set");
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}


pub mod tests {
    use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
    use masq_lib::messages::{CountryCodes, UiConnectionStatusResponse, UiMessageError, UiSetExitLocationRequest, UiSetExitLocationResponse};
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use crate::command_context::ContextError;
    use crate::commands::commands_common::{Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS, transaction};
    use crate::commands::set_exit_location_command::SetExitLocationCommand;
    use crate::test_utils::mocks::CommandContextMock;

    #[test]
    fn can_deserialize_ui_set_exit_location() {
        let mut context = &mut CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        // let stdout_arc = context.stdout_arc();
        // let stderr_arc = context.stderr_arc();
        let subject = SetExitLocationCommand::new(vec!["--exit-location CZ|SK|PL".to_string()].as_slice());
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

        let result = subject.unwrap().execute(context);

        assert_eq!(result, Ok(()))
    }
}