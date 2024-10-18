use clap::{App, SubCommand};
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::messages::{UiCollectNeighborhoodInfoRequest, UiCollectNeighborhoodInfoResponse};
use masq_lib::short_writeln;
use crate::command_context::CommandContext;
use crate::commands::commands_common::{Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS, transaction};
use crate::commands::commands_common::CommandError::Payload;


#[derive(Debug)]

pub struct NeighborhoodInfoCommand {}

const NEIGHBORHOOD_INFO_SUBCOMMAND_ABOUT: &str =
    "Example about for Neighborhood Info Command.";

pub fn neighborhood_info_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("neighborhood-info").about(NEIGHBORHOOD_INFO_SUBCOMMAND_ABOUT)
}

impl Command for NeighborhoodInfoCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiCollectNeighborhoodInfoRequest {};
        let output: Result<UiCollectNeighborhoodInfoResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);

        // TODO GH-469: Add formatting here & create test...
        match output {
            Ok(response) => {
                process_command_response(response, context);
                // short_writeln!(context.stdout(), "NeighborhoodInfo Command msg -- TODO {:?}", response);
                Ok(())
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                short_writeln!(
                    context.stderr(),
                    "MASQNode is not running; therefore neighborhood information cannot be displayed."
                );
                Err(Payload(code, message))
            }
            Err(e) => {
                short_writeln!(context.stderr(), "Neighborhood information retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }
}

impl Default for NeighborhoodInfoCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighborhoodInfoCommand {
    pub fn new() -> Self {
        Self {}
    }
}



fn process_command_response(response: UiCollectNeighborhoodInfoResponse, context: &mut dyn CommandContext) {
    fn wrap_text(text: &str, width: usize) -> Vec<String> {
        let mut result = Vec::new();
        let mut start = 0;

        while start < text.len() {
            let end = (start + width).min(text.len());
            let line = &text[start..end];
            result.push(line.to_string());
            start = end;
        }

        result
    }


    short_writeln!(context.stdout(),"{:<15} {:<10} {:<15} {:<15}","Public Key", "Version", "Country Code", "Exit Service");
    short_writeln!(context.stdout(),"{}", "-".repeat(55));

    for (node, info) in &response.neighborhood_database {
        let country_code = info.country_code_opt.as_deref().unwrap_or("N/A");
        let exit_service = if info.exit_service { "Yes" } else { "No" };
        short_writeln!(context.stdout(),
            "{:<15} {:<10} {:<15} {:<15}",
            node,
            info.version,
            country_code,
            exit_service
        );
    }

    short_writeln!(context.stdout(),"");
    short_writeln!(context.stdout(),"{:<15} {:<10}","Public Key", "Unreachable Hosts");
    short_writeln!(context.stdout(),"{}", "-".repeat(33));

    for (node, info) in &response.neighborhood_database {
        let unreachable_hosts = if info.unreachable_hosts.is_empty() {
            "None".to_string()
        } else {
            info.unreachable_hosts.join(", ")
        };

        let wrapped_hosts = wrap_text(&unreachable_hosts, 75);

        for (i, line) in wrapped_hosts.iter().enumerate() {
            if i == 0 {
                short_writeln!(context.stdout(), "{:<15} {:<75}", node, line);
            } else {
                short_writeln!(context.stdout(), "{:<15} {:<75}", "", line);
            }
        }
    }
}





#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
    use masq_lib::messages::{NodeInfo, ToMessageBody, UiCollectNeighborhoodInfoRequest, UiCollectNeighborhoodInfoResponse};
    use crate::command_context::ContextError;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::{Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::commands::neighborhood_info_command::{NEIGHBORHOOD_INFO_SUBCOMMAND_ABOUT, NeighborhoodInfoCommand};
    use crate::test_utils::mocks::CommandContextMock;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            NEIGHBORHOOD_INFO_SUBCOMMAND_ABOUT,
            "Example about for Neighborhood Info Command."
        );
    }

    #[test]
    fn testing_command_factory() {
        let factory = CommandFactoryReal::new();
        let expect_result = HashMap::from([
            (
                "public_key_1".to_string(),
                NodeInfo {
                    version: 252,
                    country_code_opt: Some("UK".to_string()),
                    exit_service: true,
                    unreachable_hosts: vec!["facebook.com".to_string(), "x.com".to_string()],
                },
            ),
            (
                "public_key_2".to_string(),
                NodeInfo {
                    version: 5,
                    country_code_opt: Some("CZ".to_string()),
                    exit_service: false,
                    unreachable_hosts: vec!["example.com".to_string()],
                },
            ),
        ]);
        let mut context = CommandContextMock::new().transact_result(Ok(UiCollectNeighborhoodInfoResponse {
            neighborhood_database: expect_result,
        }.tmb(0)));
        let subject = factory.make(&["neighborhood-info".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = NeighborhoodInfoCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::Payload(
                NODE_NOT_RUNNING_ERROR,
                "irrelevant".to_string()
            ))
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MASQNode is not running; therefore neighborhood information cannot be displayed.\n"
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
    }


    #[test]
    fn descriptor_command_bad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = NeighborhoodInfoCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiCollectNeighborhoodInfoRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Neighborhood information retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }


    #[test]
    fn testing_command_format() {
        let factory = CommandFactoryReal::new();
        let expect_result = HashMap::from([
            (
                "public_key_1".to_string(),
                NodeInfo {
                    version: 252,
                    country_code_opt: Some("UK".to_string()),
                    exit_service: true,
                    unreachable_hosts: vec!["facebook.com".to_string(), "x.com".to_string()],
                },
            ),
            (
                "public_key_2".to_string(),
                NodeInfo {
                    version: 5,
                    country_code_opt: Some("CZ".to_string()),
                    exit_service: false,
                    unreachable_hosts: vec!["example.com".to_string(), "x.com".to_string(), "youtube.com".to_string(), "google.com".to_string(), "masq.ai".to_string(), "fish.org".to_string(), "someverrrrrrrrrrylooooooooooooongurl.org".to_string(), "akc.org".to_string(), "notahost.com".to_string()],
                },
            ),
            (
                "public_key_3".to_string(),
                NodeInfo {
                    version: 65,
                    country_code_opt: None,
                    exit_service: true,
                    unreachable_hosts: vec![],
                },
            )
        ]);
        let mut context = CommandContextMock::new().transact_result(Ok(UiCollectNeighborhoodInfoResponse {
            neighborhood_database: expect_result,
        }.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let subject = factory.make(&["neighborhood-info".to_string()]).unwrap();

        let command_result = subject.execute(&mut context);
        let stdout_string= stdout_arc.lock().unwrap().get_string();

        eprintln!("{}", stdout_string);

        assert_eq!(command_result, Ok(()));
        let lines: Vec<&str> = stdout_string.lines().collect();
        assert!(lines.contains(&"Public Key      Version    Country Code    Exit Service   "));
        assert!(lines.contains(&"-------------------------------------------------------"));
        assert!(lines.contains(&"public_key_1    252        UK              Yes            "));
        assert!(lines.contains(&"public_key_2    5          CZ              No             "));
        assert!(lines.contains(&"public_key_3    65         N/A             Yes            "));
        assert!(lines.contains(&"Public Key      Unreachable Hosts"));
        assert!(lines.contains(&"---------------------------------"));
        assert!(lines.contains(&"public_key_1    facebook.com, x.com                                                        "));
        assert!(lines.contains(&"public_key_2    example.com, x.com, youtube.com, google.com, masq.ai, fish.org, someverrrrr"));
        assert!(lines.contains(&"                rrrrrylooooooooooooongurl.org, akc.org, notahost.com                       "));
        assert!(lines.contains(&"public_key_3    None                                                                       "));
    }

}