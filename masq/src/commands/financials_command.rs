// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{CustomQueries, RangeQuery, UiFinancialsRequest, UiFinancialsResponse};
use masq_lib::shared_schema::common_validators::{validate_non_zero_usize, validate_u64_range};
use masq_lib::short_writeln;
use std::cell::RefCell;
use std::fmt::Debug;

const FINANCIALS_SUBCOMMAND_ABOUT: &str =
    "Displays financial statistics of this Node. Only valid if Node is already running.";

const TOP_ARG_HELP: &str = unimplemented!();

const PAYABLE_ARG_HELP: &str = unimplemented!();

const RECEIVABLE_ARG_HELP: &str = unimplemented!();

const NO_STATS_ARG_HELP: &str = unimplemented!();

#[derive(Debug)]
pub struct FinancialsCommand {
    stats: bool,
    top_records_opt: Option<usize>,
    custom_queries_opt: RefCell<Option<CustomQueries>>,
}

pub fn financials_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("financials")
        .about(FINANCIALS_SUBCOMMAND_ABOUT)
        .arg(
            Arg::with_name("top")
                .help(TOP_ARG_HELP)
                .value_name("TOP")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .validator(validate_non_zero_usize),
        )
        .arg(
            Arg::with_name("payable")
                .help(PAYABLE_ARG_HELP)
                .value_name("PAYABLE")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .value_delimiter(" ")
                .number_of_values(2)
                .validator(validate_u64_range),
        )
        .arg(
            Arg::with_name("receivable")
                .help(RECEIVABLE_ARG_HELP)
                .value_name("PAYABLE")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .value_delimiter(" ")
                .number_of_values(2)
                .validator(validate_u64_range),
        )
        .arg(
            Arg::with_name("no-stats")
                .help(NO_STATS_ARG_HELP)
                .value_name("NO-STATS")
                .required(false)
                .case_insensitive(false)
                .takes_value(false),
        )
}

impl Command for FinancialsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiFinancialsRequest {
            stats: self.stats,
            top_records_opt: self.top_records_opt,
            custom_queries_opt: self.custom_queries_opt.take(),
        };
        let output: Result<UiFinancialsResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(response) => {
                let stdout = context.stdout();
                if let Some(stats) = response.stats_opt {
                    short_writeln!(stdout, "Financial status totals in Gwei\n");
                    dump_parameter_line(
                        stdout,
                        "Unpaid and pending payable:",
                        &stats.total_unpaid_and_pending_payable.to_string(),
                    );
                    dump_parameter_line(
                        stdout,
                        "Paid payable:",
                        &stats.total_paid_payable.to_string(),
                    );
                    dump_parameter_line(
                        stdout,
                        "Unpaid receivable:",
                        &stats.total_unpaid_receivable.to_string(),
                    );
                    dump_parameter_line(
                        stdout,
                        "Paid receivable:",
                        &stats.total_paid_receivable.to_string(),
                    );
                }
                Ok(())
            }
            Err(e) => {
                short_writeln!(context.stderr(), "Financials retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }
}

impl FinancialsCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match financials_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(e.to_string()),
        };
        let stats = matches.is_present("no-stats");
        let top_records_opt = matches.value_of("top").map(|str| {
            str.parse::<usize>()
                .expect("top records count not properly required")
        });
        let custom_payable_opt = matches
            .values_of_lossy("payable")
            .map(|vals| Self::parse_range_query(&vals[0]));
        let custom_receivable_opt = matches
            .values_of_lossy("receivable")
            .map(|vals| Self::parse_range_query(&vals[1]));
        Ok(Self {
            stats,
            top_records_opt,
            custom_queries_opt: RefCell::new(match (&custom_payable_opt, &custom_receivable_opt) {
                (None, None) => None,
                _ => Some(CustomQueries {
                    payable_opt: custom_payable_opt,
                    receivable_opt: custom_receivable_opt,
                }),
            }),
        })
    }

    fn parse<N: std::str::FromStr>(str_val: &str, name: &str) -> N {
        str::parse::<N>(str_val).unwrap_or_else(|_| panic!("{} non properly required", name))
    }

    fn parse_range_query<T>(double: &str) -> RangeQuery<T> {
        let params = double.split("-").collect::<Vec<&str>>();
        RangeQuery {
            min_age: Self::parse(params[0][0], "min_age"),
            max_age: Self::parse(params[0][1], "max_age"),
            min_amount: Self::parse(params[1][0], "min_amount"),
            max_amount: Self::parse(params[1][1], "max_amount"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{
        CustomQueryResult, FinancialStatistics, FirmQueryResult, ToMessageBody,
        UiFinancialsResponse,
    };
    use masq_lib::utils::array_of_borrows_to_vec;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            FINANCIALS_SUBCOMMAND_ABOUT,
            "Displays financial statistics of this Node. Only valid if Node is already running."
        );
    }

    #[test]
    fn command_factory_basic_command_with_defaults() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiFinancialsResponse {
            stats_opt: Some(FinancialStatistics {
                total_unpaid_and_pending_payable: 0,
                total_paid_payable: 1111,
                total_unpaid_receivable: 2222,
                total_paid_receivable: 3333,
            }),
            top_records_opt: None,
            custom_query_records_opt: None,
        }
        .tmb(0)));
        let subject = factory.make(&["financials".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn command_factory_top_records_without_stats() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: Some(FirmQueryResult {
                payable: vec![],
                receivable: vec![],
            }),
            custom_query_records_opt: None,
        }
        .tmb(0)));
        let subject = factory
            .make(&["financials top 20 no-stats".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn command_factory_everything_demanded() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiFinancialsResponse {
            stats_opt: Some(FinancialStatistics {
                total_unpaid_and_pending_payable: 0,
                total_paid_payable: 1111,
                total_unpaid_receivable: 2222,
                total_paid_receivable: 3333,
            }),
            top_records_opt: Some(FirmQueryResult {
                payable: vec![],
                receivable: vec![],
            }),
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: Some(vec![]),
                receivable_opt: None,
            }),
        }
        .tmb(0)));
        let subject = factory
            .make(&array_of_borrows_to_vec(&[
                "financials",
                "top",
                "10",
                "payable",
                "200-450",
                "48000000111-158000008000",
            ]))
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn default_financials_command_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(FinancialStatistics {
                total_unpaid_and_pending_payable: 116688,
                total_paid_payable: 55555,
                total_unpaid_receivable: 221144,
                total_paid_receivable: 66555,
            }),
            top_records_opt: None,
            custom_query_records_opt: None,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let args = &["financials".to_string()];
        let subject = FinancialsCommand::new(args);

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats: true,
                    top_records_opt: None,
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\
                Financial status totals in Gwei\n\
                \n\
                Unpaid and pending payable:       116688\n\
                Paid payable:                     55555\n\
                Unpaid receivable:                221144\n\
                Paid receivable:                  66555\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let args = &["financials".to_string()];
        let subject = FinancialsCommand::new(args);

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats: true,
                    top_records_opt: None,
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Financials retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
