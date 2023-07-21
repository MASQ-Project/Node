use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{App, Arg, ArgGroup, SubCommand};
use masq_lib::implement_as_any;
use masq_lib::messages::{UiSetConfigurationRequest, UiSetConfigurationResponse};
use masq_lib::shared_schema::gas_price_arg;
use masq_lib::shared_schema::min_hops_arg;
use masq_lib::short_writeln;
use masq_lib::utils::ExpectValue;
#[cfg(test)]
use std::any::Any;

#[derive(Debug, PartialEq, Eq)]
pub struct SetConfigurationCommand {
    pub name: String,
    pub value: String,
}

impl SetConfigurationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let parameter_opt = pieces.get(1).map(|s| &s[2..]);
        match set_configuration_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => {
                let parameter = parameter_opt.expectv("required param");
                Ok(SetConfigurationCommand {
                    name: parameter.to_string(),
                    value: matches
                        .value_of(parameter)
                        .expectv("required param")
                        .to_string(),
                })
            }

            Err(e) => Err(format!("{}", e)),
        }
    }
}

fn validate_start_block(start_block: String) -> Result<(), String> {
    match start_block.parse::<u64>() {
        Ok(_) => Ok(()),
        _ => Err(start_block),
    }
}

impl Command for SetConfigurationCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiSetConfigurationRequest {
            name: self.name.clone(),
            value: self.value.clone(),
        };

        let _: UiSetConfigurationResponse = transaction(input, context, 1000)?;
        short_writeln!(context.stdout(), "Parameter was successfully set");
        Ok(())
    }

    implement_as_any!();
}

const SET_CONFIGURATION_ABOUT: &str =
    "Sets Node configuration parameters being enabled for this operation when the Node is running.";
const START_BLOCK_HELP: &str =
    "Ordinal number of the Ethereum block where scanning for transactions will start.";

pub fn set_configuration_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("set-configuration")
        .about(SET_CONFIGURATION_ABOUT)
        .arg(gas_price_arg())
        .arg(min_hops_arg())
        .arg(
            Arg::with_name("start-block")
                .help(START_BLOCK_HELP)
                .long("start-block")
                .value_name("START-BLOCK")
                .takes_value(true)
                .required(false)
                .validator(validate_start_block),
        )
        .group(
            ArgGroup::with_name("parameter")
                .args(&["gas-price", "min-hops", "start-block"])
                .required(true),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::CommandContextMock;
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
            .get_matches_from_safe(&[
                "set-configuration",
                "--gas-price",
                "70",
                "--start-block",
                "44444",
            ])
            .unwrap_err()
            .to_string();
        assert!(result.contains("cannot be used with one or more of the other specified arguments"));
    }

    #[test]
    fn validate_start_block_works() {
        assert!(validate_start_block("abc".to_string()).is_err());
        assert!(validate_start_block("1566".to_string()).is_ok());
    }

    #[test]
    fn command_execution_works_all_fine() {
        test_command_execution("--start-block", "123456");
        test_command_execution("--gas-price", "123456");
        test_command_execution("--min-hops", "6");
    }

    // TODO: This test only passes when we run through IDE - make it work even without it
    #[test]
    #[ignore]
    fn set_configuration_command_throws_err_for_invalid_arg() {
        let (invalid_arg, some_value) = ("--invalid-arg", "123");

        let result = SetConfigurationCommand::new(&[
            "set-configuration".to_string(),
            invalid_arg.to_string(),
            some_value.to_string(),
        ]);

        let err_msg = result.unwrap_err();
        assert!(err_msg.contains(
            "error: Found argument '--invalid-arg' \
             which wasn't expected, or isn't valid in this context"
        ));
    }

    fn test_command_execution(name: &str, value: &str) {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetConfigurationResponse {}.tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = SetConfigurationCommand::new(&[
            "set-configuration".to_string(),
            name.to_string(),
            value.to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetConfigurationRequest {
                    name: name[2..].to_string(),
                    value: value.to_string(),
                }
                .tmb(0),
                1000
            )]
        );
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(&stderr.get_string(), "");
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(&stdout.get_string(), "Parameter was successfully set\n");
    }
}
