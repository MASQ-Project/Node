use std::sync::{Arc, Mutex};
use clap::{App, SubCommand};
use masq_lib::{as_any_ref_in_trait_impl, short_writeln};

use masq_lib::messages::{ToMessageBody, UiGetNeighborhoodGraphRequest, UiGetNeighborhoodGraphResponse};
use crate::command_context::CommandContext;
use crate::commands::commands_common::{Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS, transaction};
use crate::commands::commands_common::CommandError::Payload;
use crate::test_utils::mocks::CommandContextMock;

const NEIGHBORHOOD_GRAPH_HELP: &str = "";

pub fn neighborhood_graph_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("neighborhood-graph").about(NEIGHBORHOOD_GRAPH_HELP)
}

#[derive(Debug, PartialEq, Eq)]
pub struct GetNeighborhoodGraphCommand {}

impl GetNeighborhoodGraphCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        match neighborhood_graph_subcommand().get_matches_from_safe(pieces) {
            Ok(_) => Ok(GetNeighborhoodGraphCommand {}),
            Err(e) => Err(format!("GetNeighborhoodGraphCommand {}", e)),
        }
    }
}

impl Command for GetNeighborhoodGraphCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiGetNeighborhoodGraphRequest {};
        let output: Result<UiGetNeighborhoodGraphResponse, CommandError> = transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(neigoborhood_graph) => {
                short_writeln!(
                    context.stdout(),
                    "Graph of the Neighborhood: {}",
                    neigoborhood_graph.graph.as_str()
                );
                Ok(())
            },
            Err(Payload(code, message)) => {
                short_writeln!(context.stderr(), "code: {}\nmessage: {}", code, message);
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

#[test]
fn can_deserialize_ui_get_neighborhood_graph() {
    let transact_params_arc = Arc::new(Mutex::new(vec![]));
    let mut context= CommandContextMock::new()
        .transact_params(&transact_params_arc)
        .transact_result(Ok(UiGetNeighborhoodGraphResponse {
            graph: "digraph db { \"AQIDBA\" [label=\"AR v0 AU\\nAQIDBA\\n1.2.3.4:1234\"]; \"HZ5vwwJPhfUZVy85E76GZUUam9SMgyaw+QaZvAMuizo\" [label=\"AR v0 ZZ\\nHZ5vwwJP\\n9.9.9.9:9999\"] [style=filled]; \"AgMEBQ\" [label=\"AR v0 FR\\nAgMEBQ\\n2.3.4.5:2345\"]; \"AwQFBg\" [label=\"AR v0 CN\\nAwQFBg\\n3.4.5.6:3456\"]; \"BAUGBw\" [label=\"AR v0 US\\nBAUGBw\\n4.5.6.7:4567\"]; \"AQIDBA\" -> \"HZ5vwwJPhfUZVy85E76GZUUam9SMgyaw+QaZvAMuizo\"; \"AQIDBA\" -> \"AgMEBQ\"; \"HZ5vwwJPhfUZVy85E76GZUUam9SMgyaw+QaZvAMuizo\" -> \"AQIDBA\"; \"AgMEBQ\" -> \"AwQFBg\"; \"AgMEBQ\" -> \"AQIDBA\"; \"AwQFBg\" -> \"BAUGBw\"; \"AwQFBg\" -> \"AgMEBQ\"; \"BAUGBw\" -> \"AwQFBg\"; }".to_string()
        }.tmb(0)));
    let stderr_arc = context.stderr_arc();
    let stdout_arc = context.stdout_arc();
    let subject = GetNeighborhoodGraphCommand::new(&[
        "neighborhood-graph".to_string(),
    ]).unwrap();

    let result = subject.execute(&mut context);

    assert_eq!(result, Ok(()));
    let expected_request = UiGetNeighborhoodGraphRequest {};
    let transact_params = transact_params_arc.lock().unwrap();
    let expected_message_body = expected_request.tmb(0);
    assert_eq!(
        transact_params.as_slice(),
        &[(expected_message_body, STANDARD_COMMAND_TIMEOUT_MILLIS)]
    );
    let stdout = stdout_arc.lock().unwrap();
    let graph_str = "Graph of the Neighborhood: digraph db { \"AQIDBA\" [label=\"AR v0 AU\\nAQIDBA\\n1.2.3.4:1234\"]; \"HZ5vwwJPhfUZVy85E76GZUUam9SMgyaw+QaZvAMuizo\" [label=\"AR v0 ZZ\\nHZ5vwwJP\\n9.9.9.9:9999\"] [style=filled]; \"AgMEBQ\" [label=\"AR v0 FR\\nAgMEBQ\\n2.3.4.5:2345\"]; \"AwQFBg\" [label=\"AR v0 CN\\nAwQFBg\\n3.4.5.6:3456\"]; \"BAUGBw\" [label=\"AR v0 US\\nBAUGBw\\n4.5.6.7:4567\"]; \"AQIDBA\" -> \"HZ5vwwJPhfUZVy85E76GZUUam9SMgyaw+QaZvAMuizo\"; \"AQIDBA\" -> \"AgMEBQ\"; \"HZ5vwwJPhfUZVy85E76GZUUam9SMgyaw+QaZvAMuizo\" -> \"AQIDBA\"; \"AgMEBQ\" -> \"AwQFBg\"; \"AgMEBQ\" -> \"AQIDBA\"; \"AwQFBg\" -> \"BAUGBw\"; \"AwQFBg\" -> \"AgMEBQ\"; \"BAUGBw\" -> \"AwQFBg\"; }\n";
    assert_eq!(&stdout.get_string(),  graph_str);
    let stderr = stderr_arc.lock().unwrap();
    assert_eq!(&stderr.get_string(), "");

}