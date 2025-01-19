use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use crate::masq_short_writeln;
use crate::terminal::WTermInterface;
use async_trait::async_trait;
use clap::builder::ValueRange;
use clap::{value_parser, Arg, ArgGroup, Command as ClapCommand};
use masq_lib::implement_as_any;
use masq_lib::messages::{UiSetConfigurationRequest, UiSetConfigurationResponse};
use masq_lib::shared_schema::{GasPrice, GAS_PRICE_HELP};
use masq_lib::utils::{get_argument_value_as_string, ExpectValue};
#[cfg(test)]
use std::any::Any;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub struct SetConfigurationCommand {
    pub name: String,
    pub value: String,
}

impl SetConfigurationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let parameter_opt = pieces.get(1).map(|s| &s[2..]);
        match set_configuration_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => {
                let parameter = parameter_opt.expectv("required param");
                Ok(SetConfigurationCommand {
                    name: parameter.to_string(),
                    value: get_argument_value_as_string(&matches, parameter)
                        .expectv("required param")
                        .to_string(),
                })
            }

            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[async_trait(?Send)]
impl Command for SetConfigurationCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let input = UiSetConfigurationRequest {
            name: self.name.clone(),
            value: self.value.clone(),
        };

        let _: UiSetConfigurationResponse = transaction(input, context, &stderr, 1000).await?;
        masq_short_writeln!(stdout, "Parameter was successfully set");
        Ok(())
    }

    implement_as_any!();
}

const SET_CONFIGURATION_ABOUT: &str =
    "Sets Node configuration parameters being enabled for this operation when the Node is running.";
const START_BLOCK_HELP: &str =
    "Ordinal number of the Ethereum block where scanning for transactions will start.";

pub fn set_configuration_subcommand() -> ClapCommand {
    ClapCommand::new("set-configuration")
        .about(SET_CONFIGURATION_ABOUT)
        .arg(
            Arg::new("gas-price")
                .help(GAS_PRICE_HELP())
                .long("gas-price")
                .value_name("GAS-PRICE")
                .num_args(ValueRange::new(1..=1))
                .required(false)
                .value_parser(value_parser!(GasPrice)),
        )
        .arg(
            Arg::new("start-block")
                .help(START_BLOCK_HELP)
                .long("start-block")
                .value_name("START-BLOCK")
                .num_args(ValueRange::new(1..=1))
                .required(false)
                .value_parser(value_parser!(u64)),
        )
        .group(
            ArgGroup::new("parameter")
                .args(&["gas-price", "start-block"])
                .required(true),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::test_utils::allow_writtings_to_finish;
    use crate::test_utils::mocks::{CommandContextMock, MockTerminalMode, TermInterfaceMock};
    use masq_lib::messages::{
        ToMessageBody, UiSetConfigurationRequest, UiSetConfigurationResponse,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            SET_CONFIGURATION_ABOUT,
            "Sets Node configuration parameters being enabled for this operation when the Node is running."
        );
        assert_eq!(
            START_BLOCK_HELP,
            "Ordinal number of the Ethereum block where scanning for transactions will start."
        );
    }

    #[test]
    fn only_one_parameter_at_a_time_is_permitted() {
        let result = set_configuration_subcommand()
            .try_get_matches_from(&[
                "set-configuration",
                "--gas-price",
                "70",
                "--start-block",
                "44444",
            ])
            .unwrap_err()
            .to_string();
        assert!(result.contains("cannot be used with"), "{}", result);
    }

    #[tokio::test]
    async fn command_execution_works_all_fine() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetConfigurationResponse {}.tmb(4321)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = SetConfigurationCommand {
            name: "start-block".to_string(),
            value: "123456".to_string(),
        };

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_writtings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetConfigurationRequest {
                    name: "start-block".to_string(),
                    value: "123456".to_string()
                }
                .tmb(0),
                1000
            )]
        );
        stream_handles.assert_empty_stderr();
        assert_eq!(
            stream_handles.stdout_all_in_one(),
            "Parameter was successfully set\n"
        );
    }
}
