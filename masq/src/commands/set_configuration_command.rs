use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{App, Arg, ArgGroup, SubCommand};
use masq_lib::messages::{UiSetConfigurationRequest, UiSetConfigurationResponse};
use masq_lib::shared_schema::common_validators;
use masq_lib::shared_schema::GAS_PRICE_HELP;
use masq_lib::short_writeln;
use std::any::Any;

#[derive(Debug, PartialEq)]
pub struct SetConfigurationCommand {
    pub name: String,
    pub value: String,
}

impl SetConfigurationCommand {
    pub fn new(pieces: Vec<String>) -> Result<Self, String> {
        // if anything wrong, Clap will handle it at get_matches_from_safe
        let mut preserved_name: String = String::new();
        if pieces.len() != 1 {
            preserved_name.push_str(&pieces[1].clone().replace("--", ""))
        };
        match set_configuration_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => Ok(SetConfigurationCommand {
                name: preserved_name.clone(),
                value: matches
                    .value_of(preserved_name)
                    .expect("should not reach this state")
                    .to_string(),
            }),
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn set_configuration_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("set-configuration")
        .about("Sets Node configuration parameters being enabled for this operation when the Node is running")
        .arg(
            Arg::with_name("gas-price")
                .help(&GAS_PRICE_HELP)
                .long("gas-price")
                .value_name("GAS-PRICE")
                .takes_value(true)
                .required(false)
                .validator(common_validators::validate_gas_price)

        )
        .arg(
            Arg::with_name("start-block")
                .help("Ordinal number of the Ethereum block where scanning for transactions will start.")
                .long("start-block")
                .value_name("START-BLOCK")
                .takes_value(true)
                .required(false)
                .validator(validate_start_block)
        )
        .group (
        ArgGroup::with_name("parameter")
            .args( &["gas-price","start-block"] )
            .required (true)
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
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetConfigurationResponse {}.tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = SetConfigurationCommand {
            name: "start-block".to_string(),
            value: "123456".to_string(),
        };

        let result = subject.execute(&mut context);

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
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(*stderr.get_string(), String::new());
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(&stdout.get_string(), "Parameter was successfully set\n");
    }
}
