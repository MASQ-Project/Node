// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod args_validation;
pub mod data_structures;
pub mod parsing_and_value_dressing;
pub mod pretty_print_utils;
#[cfg(test)]
pub mod test_utils;

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::commands::financials_command::args_validation::{
    financials_subcommand, NonZeroU16, TwoRanges,
};
use crate::commands::financials_command::data_structures::restricted::ProcessAccountsMetadata;
use crate::commands::financials_command::pretty_print_utils::restricted::process_gwei_into_requested_format;
use crate::commands::financials_command::pretty_print_utils::restricted::{
    financial_status_totals_title, main_title_for_tops_opt, no_records_found, prepare_metadata,
    render_accounts_generic, subtitle_for_tops, triple_or_single_blank_line,
    StringValuesFormattableAccount,
};
use crate::commands::parameter_columns_formatting::dump_parameter_line;
use crate::masq_short_writeln;
use crate::terminal::{TerminalWriter, WTermInterface};
use async_trait::async_trait;
use clap::ArgMatches;
use masq_lib::messages::{
    CustomQueries, QueryResults, RangeQuery, TopRecordsConfig, TopRecordsOrdering,
    UiFinancialStatistics, UiFinancialsRequest, UiFinancialsResponse,
};
use masq_lib::utils::ExpectValue;
use num::ToPrimitive;

#[derive(Debug, PartialEq, Eq)]
pub struct FinancialsCommand {
    stats_required: bool,
    gwei_precision: bool,
    top_records_opt: Option<TopRecordsConfig>,
    custom_queries_opt: Option<CustomQueries>,
}

#[async_trait(?Send)]
impl Command for FinancialsCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let input = UiFinancialsRequest {
            stats_required: self.stats_required,
            top_records_opt: self.top_records_opt,
            custom_queries_opt: self.custom_queries_opt.as_ref().map(|cq| cq.clone()),
        };
        let queries_opt = input.custom_queries_opt.clone();
        let output: Result<UiFinancialsResponse, CommandError> =
            transaction(input, context, &stderr, STANDARD_COMMAND_TIMEOUT_MILLIS).await;
        match output {
            Ok(response) => {
                self.process_command_response(queries_opt, response, &stdout)
                    .await
            }
            Err(e) => {
                masq_short_writeln!(stderr, "Financials retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }
}

impl FinancialsCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match financials_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(e.to_string()),
        };
        let stats_required = !matches.get_flag("no-stats");
        let top_records_opt = Self::parse_top_records_args(&matches);
        let gwei_precision = matches.get_flag("gwei");
        let custom_queries_opt = Self::parse_custom_query_args(&matches)?;
        Ok(Self {
            stats_required,
            top_records_opt,
            custom_queries_opt,
            gwei_precision,
        })
    }

    async fn process_command_response(
        &self,
        queries_opt: Option<CustomQueries>,
        response: UiFinancialsResponse,
        stdout: &TerminalWriter,
    ) -> Result<(), CommandError> {
        if let Some(ref stats) = response.stats_opt {
            self.process_financial_statistics(stdout, stats, self.gwei_precision)
                .await
        };
        if let Some(results) = response.query_results_opt {
            self.process_queried_records(
                queries_opt,
                stdout,
                results,
                response.stats_opt.is_none(),
                self.gwei_precision,
            )
            .await
        }
        Ok(())
    }

    async fn process_financial_statistics(
        &self,
        stdout: &TerminalWriter,
        stats: &UiFinancialStatistics,
        gwei_flag: bool,
    ) {
        financial_status_totals_title(stdout, gwei_flag).await;
        dump_parameter_line(
            stdout,
            "Unpaid and pending payable:",
            None,
            &process_gwei_into_requested_format(
                stats.total_unpaid_and_pending_payable_gwei,
                gwei_flag,
            ),
        )
        .await;
        dump_parameter_line(
            stdout,
            "Paid payable:",
            None,
            &process_gwei_into_requested_format(stats.total_paid_payable_gwei, gwei_flag),
        )
        .await;
        dump_parameter_line(
            stdout,
            "Unpaid receivable:",
            None,
            &process_gwei_into_requested_format(stats.total_unpaid_receivable_gwei, gwei_flag),
        )
        .await;
        dump_parameter_line(
            stdout,
            "Paid receivable:",
            None,
            &process_gwei_into_requested_format(stats.total_paid_receivable_gwei, gwei_flag),
        )
        .await;
    }

    async fn process_queried_records(
        &self,
        queries_opt: Option<CustomQueries>,
        stdout: &TerminalWriter,
        returned_records: QueryResults,
        is_first_printed_thing: bool,
        gwei_flag: bool,
    ) {
        let is_both_sets = self.are_both_sets_to_be_displayed();
        let (payable_metadata, receivable_metadata) = prepare_metadata(gwei_flag);

        triple_or_single_blank_line(stdout, is_first_printed_thing).await;
        main_title_for_tops_opt(self, stdout).await;
        self.process_returned_records_in_requested_mode(
            returned_records.payable_opt,
            stdout,
            payable_metadata,
            Self::flat_map_option(&queries_opt, |q| q.payable_opt.clone()),
        )
        .await;
        if is_both_sets {
            triple_or_single_blank_line(stdout, false).await
        }
        self.process_returned_records_in_requested_mode(
            returned_records.receivable_opt,
            stdout,
            receivable_metadata,
            Self::flat_map_option(&queries_opt, |q| q.receivable_opt.clone()),
        )
        .await;
    }

    fn flat_map_option<A, B, F>(input: &Option<A>, closure: F) -> Option<B>
    where
        F: FnOnce(&A) -> Option<B>,
    {
        match input {
            None => None,
            Some(a) => closure(a),
        }
    }

    fn are_both_sets_to_be_displayed(&self) -> bool {
        self.top_records_opt.is_some()
            || (if let Some(custom_queries) = self.custom_queries_opt.as_ref() {
                custom_queries.payable_opt.is_some() && custom_queries.receivable_opt.is_some()
            } else {
                false
            })
    }

    async fn process_returned_records_in_requested_mode<A, R>(
        &self,
        returned_records_opt: Option<Vec<A>>,
        stdout: &TerminalWriter,
        metadata: ProcessAccountsMetadata,
        range_query_opt: Option<RangeQuery<R>>,
    ) where
        A: StringValuesFormattableAccount,
        R: ToPrimitive,
    {
        if self.top_records_opt.is_some() {
            subtitle_for_tops(stdout, metadata.table_type).await;
            let accounts = returned_records_opt.expectv(metadata.table_type);
            if !accounts.is_empty() {
                render_accounts_generic(stdout, accounts, &metadata.headings).await;
            } else {
                no_records_found(stdout, metadata.headings.words.as_slice()).await
            }
        } else if let Some(range_query) = range_query_opt {
            TwoRanges::title_for_custom_query(stdout, metadata.table_type, range_query).await;
            if let Some(accounts) = returned_records_opt {
                render_accounts_generic(stdout, accounts, &metadata.headings).await
            } else {
                no_records_found(stdout, metadata.headings.words.as_slice()).await
            }
        }
    }

    fn parse_top_records_args(matches: &ArgMatches) -> Option<TopRecordsConfig> {
        matches
            .get_one::<NonZeroU16>("top")
            .map(|nzu16| TopRecordsConfig {
                count: nzu16.data,
                ordered_by: *matches
                    .get_one::<TopRecordsOrdering>("ordered")
                    .expect("should be required and defaulted"),
            })
    }

    fn parse_custom_query_args(matches: &ArgMatches) -> Result<Option<CustomQueries>, String> {
        match (
            Self::parse_range_for_query_u(matches, "payable"),
            Self::parse_range_for_query_i(matches, "receivable"),
        ) {
            (None, None) => Ok(None),
            (Some(Ok(payable)), Some(Ok(receivable))) => Ok(Some(CustomQueries {
                payable_opt: Some(payable),
                receivable_opt: Some(receivable),
            })),
            (Some(Ok(payable)), None) => Ok(Some(CustomQueries {
                payable_opt: Some(payable),
                receivable_opt: None,
            })),
            (None, Some(Ok(receivable))) => Ok(Some(CustomQueries {
                payable_opt: None,
                receivable_opt: Some(receivable),
            })),
            (Some(Err(p)), Some(Err(r))) => Err(format!("Payable: {}; Receivable: {}", p, r)),
            (Some(Err(p)), _) => Err(format!("Payable: {}", p)),
            (_, Some(Err(r))) => Err(format!("Receivable: {}", r)),
        }
    }

    fn parse_range_for_query_u(
        matches: &ArgMatches,
        parameter_name: &str,
    ) -> Option<Result<RangeQuery<u64>, String>> {
        match matches.get_one::<TwoRanges>(parameter_name) {
            None => None,
            Some(two_ranges) => Some(two_ranges.try_convert_with_limit_u(i64::MAX as i128)),
        }
    }

    fn parse_range_for_query_i(
        matches: &ArgMatches,
        parameter_name: &str,
    ) -> Option<Result<RangeQuery<i64>, String>> {
        match matches.get_one::<TwoRanges>(parameter_name) {
            None => None,
            Some(two_ranges) => Some(two_ranges.try_convert_with_limit_i(i64::MAX as i128)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryError, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::commands::financials_command::args_validation::financials_subcommand;
    use crate::terminal::test_utils::allow_flushed_writings_to_finish;
    use crate::test_utils::mocks::{CommandContextMock, TermInterfaceMock};
    use atty::Stream;
    use masq_lib::messages::{
        ToMessageBody, TopRecordsOrdering, UiFinancialStatistics, UiFinancialsResponse,
        UiPayableAccount, UiReceivableAccount,
    };
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::utils::slice_of_strs_to_vec_of_strings;
    use regex::Regex;
    use std::sync::{Arc, Mutex};
    use std::vec;

    fn meaningless_financials_response() -> MessageBody {
        UiFinancialsResponse {
            stats_opt: None,
            query_results_opt: None,
        }
        .tmb(0)
    }

    #[tokio::test]
    async fn command_factory_default_command() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Ok(meaningless_financials_response()))
            .transact_params(&transact_params_arc);
        let (mut term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = factory.make(&["financials".to_string()]).unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[tokio::test]
    async fn command_factory_top_records_without_stats() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Ok(meaningless_financials_response()))
            .transact_params(&transact_params_arc);
        let (mut term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = factory
            .make(&slice_of_strs_to_vec_of_strings(&[
                "financials",
                "--top",
                "20",
                "--no-stats",
            ]))
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 20,
                        ordered_by: TopRecordsOrdering::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[tokio::test]
    async fn command_factory_everything_demanded_with_top_records() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Ok(meaningless_financials_response()))
            .transact_params(&transact_params_arc);
        let (mut term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = factory
            .make(&slice_of_strs_to_vec_of_strings(&[
                "financials",
                "--top",
                "10",
                "--gwei",
            ]))
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 10,
                        ordered_by: TopRecordsOrdering::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[tokio::test]
    async fn command_factory_everything_demanded_with_custom_queries() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Ok(meaningless_financials_response()))
            .transact_params(&transact_params_arc);
        let (mut term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = factory
            .make(&slice_of_strs_to_vec_of_strings(&[
                "financials",
                "--payable",
                "200-450|480000-15800008",
                "--receivable",
                "5000-10000|0.003000000-5.600070000",
                "--gwei",
            ]))
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 200,
                            max_age_s: 450,
                            min_amount_gwei: 480_000_000_000_000,
                            max_amount_gwei: 15_800_008_000_000_000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 5000,
                            max_age_s: 10000,
                            min_amount_gwei: 3000000,
                            max_amount_gwei: 5600070000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[test]
    fn supplied_big_masq_values_are_not_fatal_for_non_decimal_values() {
        let factory = CommandFactoryReal::new();
        let result = factory
            .make(&slice_of_strs_to_vec_of_strings(&[
                "financials",
                "--payable",
                "200-450|480000-15800000800045",
            ]))
            .unwrap_err();
        let err = match result {
            CommandFactoryError::CommandSyntax(msg) => msg,
            x => panic!("we expected CommandSyntax error but got: {:?}", x),
        };

        assert!(err.contains("Amount bigger than the MASQ total supply: 15800000800045"))
    }

    #[test]
    fn supplied_big_masq_values_are_not_fatal_for_decimal_values() {
        let factory = CommandFactoryReal::new();
        let result = factory
            .make(&slice_of_strs_to_vec_of_strings(&[
                "financials",
                "--payable",
                "200-450|480045454455.00-158000008000455",
            ]))
            .unwrap_err();
        let err = match result {
            CommandFactoryError::CommandSyntax(msg) => msg,
            x => panic!("we expected CommandSyntax error but got: {:?}", x),
        };

        assert!(
            err.contains("Amount bigger than the MASQ total supply: 480045454455.00"),
            "{}",
            err
        )
    }

    #[test]
    fn command_factory_no_stats_arg_is_forbidden_if_no_other_arg_present() {
        let factory = CommandFactoryReal::new();

        let result = factory.make(&slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--no-stats",
        ]));

        let err = match result {
            Err(CommandFactoryError::CommandSyntax(err_msg)) => err_msg,
            x => panic!("we expected CommandSyntax error but got: {:?}", x),
        };
        assert!(
            err.contains("the following required arguments were not provided:"),
            "{}",
            err
        );
    }

    fn top_records_mutual_exclusivity_assertion(
        args: &[&str],
        affected_parameters: &[(&str, bool)],
    ) {
        let factory = CommandFactoryReal::new();

        let result = factory.make(&slice_of_strs_to_vec_of_strings(args));

        let err = match result {
            Ok(_) => panic!("we expected error but got ok"),
            Err(CommandFactoryError::CommandSyntax(err_msg)) => err_msg,
            Err(e) => panic!("we expected CommandSyntax error but got: {:?}", e),
        };
        assert_on_text_simply_in_ide_and_otherwise_in_terminal(&err, affected_parameters);
        assert!(err.contains("cannot be used with"), "{}", err);
        assert!(err.contains("Usage:"))
    }

    fn assert_on_text_simply_in_ide_and_otherwise_in_terminal(
        err: &str,
        searched_words: &[(&str, bool)],
    ) {
        fn with_quotes(quotes: bool) -> &'static str {
            if quotes {
                "'"
            } else {
                ""
            }
        }
        searched_words.iter().for_each(|(string, quotes)| {
            if atty::is(Stream::Stderr) {
                let regex = Regex::new(&format!("\x1B\\[.*m{}\x1B\\[0m", string)).unwrap();
                assert!(
                    regex.is_match(&err),
                    "the regex didn't chase {} down here: {}",
                    string,
                    err
                )
            } else {
                let quote_str = with_quotes(*quotes);
                assert!(
                    err.contains(&format!("{}{}{}", quote_str, string, quote_str)),
                    "Substring {}{}{} was not found in:\n------\n{}\n------",
                    quote_str,
                    string,
                    quote_str,
                    err
                )
            }
        })
    }

    #[test]
    fn command_factory_top_records_and_payable_custom_query_are_mutually_exclusive() {
        top_records_mutual_exclusivity_assertion(
            &["financials", "--top", "15", "--payable", "5-100|600-7000"],
            &[("--payable <PAYABLE>", false)],
        )
    }

    #[test]
    fn command_factory_top_records_and_receivable_custom_query_are_mutually_exclusive() {
        top_records_mutual_exclusivity_assertion(
            &[
                "financials",
                "--top",
                "15",
                "--receivable",
                "5-100|600-7000",
            ],
            &[("--receivable <RECEIVABLE>", false)],
        )
    }

    #[test]
    fn ordered_can_be_combined_with_top_records_only() {
        let factory = CommandFactoryReal::new();

        let result = factory.make(&slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--receivable",
            "5-100|600-7000",
            "--ordered",
            "age",
        ]));

        let err = match result {
            Ok(_) => panic!("we expected error but got ok"),
            Err(CommandFactoryError::CommandSyntax(err_msg)) => err_msg,
            Err(e) => panic!("we expected CommandSyntax error but got: {:?}", e),
        };
        assert_on_text_simply_in_ide_and_otherwise_in_terminal(
            &err,
            &[("--receivable <RECEIVABLE>", false)],
        );
        assert!(err.contains("cannot be used with"), "{}", err);
        assert!(err.contains("Usage"))
    }

    #[tokio::test]
    async fn financials_command_allows_shorthands_even_with_top_records() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "-g",
            "-t",
            "123",
            "-o",
            "balance",
            "-n",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(meaningless_financials_response()));
        let (mut term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 123,
                        ordered_by: TopRecordsOrdering::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[tokio::test]
    async fn financials_command_allows_shorthands_even_with_custom_query() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "-g",
            "-p",
            "0-350000|0.005-9.000000000",
            "-r",
            "5000-10000|0.000004000-50.003000000",
            "-n",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(meaningless_financials_response()));
        let (mut term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 0,
                            max_age_s: 350000,
                            min_amount_gwei: 5000000,
                            max_amount_gwei: 9_000_000_000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 5000,
                            max_age_s: 10000,
                            min_amount_gwei: 4000,
                            max_amount_gwei: 50_003_000_000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[tokio::test]
    async fn financials_command_top_records_ordered_by_age_and_not_balance() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--no-stats",
            "--top",
            "7",
            "-o",
            "age",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(meaningless_financials_response()));
        let (mut term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 7,
                        ordered_by: TopRecordsOrdering::Age
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[test]
    fn parse_top_records_arg_with_ordered_defaulted_to_balance() {
        let args = slice_of_strs_to_vec_of_strings(&["financials", "--top", "11"]);
        let matches = financials_subcommand().try_get_matches_from(args).unwrap();

        let result = FinancialsCommand::parse_top_records_args(&matches);

        assert_eq!(
            result,
            Some(TopRecordsConfig {
                count: 11,
                ordered_by: TopRecordsOrdering::Balance
            })
        )
    }

    #[test]
    fn financials_command_allows_obscure_leading_zeros_in_positive_numbers() {
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--receivable",
            "05000-0010000|040-050",
        ]);

        let result = FinancialsCommand::new(&args).unwrap();

        assert_eq!(
            result,
            FinancialsCommand {
                stats_required: true,
                top_records_opt: None,
                custom_queries_opt: Some(CustomQueries {
                    payable_opt: None,
                    receivable_opt: Some(RangeQuery {
                        min_age_s: 5000,
                        max_age_s: 10000,
                        min_amount_gwei: 40_000_000_000,
                        max_amount_gwei: 50_000_000_000
                    })
                }),
                gwei_precision: false
            }
        );
    }

    #[test]
    fn financials_command_allows_obscure_leading_zeros_in_negative_numbers() {
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--receivable",
            "5000-10000|-050--040",
        ]);

        let result = FinancialsCommand::new(&args).unwrap();

        assert_eq!(
            result,
            FinancialsCommand {
                stats_required: true,
                top_records_opt: None,
                custom_queries_opt: Some(CustomQueries {
                    payable_opt: None,
                    receivable_opt: Some(RangeQuery {
                        min_age_s: 5000,
                        max_age_s: 10000,
                        min_amount_gwei: -50000000000,
                        max_amount_gwei: -40000000000
                    })
                }),
                gwei_precision: false
            }
        );
    }

    #[tokio::test]
    async fn default_financials_command_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 1_166_880_215,
                total_paid_payable_gwei: 78_455_555,
                total_unpaid_receivable_gwei: -55_000_400,
                total_paid_receivable_gwei: 1_278_766_555_456,
            }),
            query_results_opt: None,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let args = &["financials".to_string()];
        let subject = FinancialsCommand::new(args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_all_in_one(),
            "\
                \n\
                Financial status totals in MASQ\n\
                \n\
                Unpaid and pending payable:       1.16\n\
                Paid payable:                     0.07\n\
                Unpaid receivable:                -0.05\n\
                Paid receivable:                  1,278.76\n"
        );
        stream_handles.assert_empty_stderr();
    }

    #[test]
    fn are_both_sets_to_be_displayed_works_for_top_records() {
        // Top records always print as paired sets
        let subject = FinancialsCommand::new(&slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--top",
            "20",
        ]))
        .unwrap();

        let result = subject.are_both_sets_to_be_displayed();

        assert_eq!(result, true)
    }

    #[test]
    fn are_both_sets_to_be_displayed_works_for_custom_query_with_payable_only() {
        let subject = FinancialsCommand::new(&slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--payable",
            "20-40|60-120",
        ]))
        .unwrap();

        let result = subject.are_both_sets_to_be_displayed();

        assert_eq!(result, false)
    }

    #[test]
    fn are_both_sets_to_be_displayed_works_for_custom_query_with_receivable_only() {
        let subject = FinancialsCommand::new(&slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--receivable",
            "20-40|-50-120",
        ]))
        .unwrap();

        let result = subject.are_both_sets_to_be_displayed();

        assert_eq!(result, false)
    }

    #[test]
    fn are_both_sets_to_be_displayed_works_for_custom_query_with_both_parts() {
        let subject = FinancialsCommand::new(&slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--receivable",
            "20-40|-50-120",
            "--payable",
            "15-55|667-800",
        ]))
        .unwrap();

        let result = subject.are_both_sets_to_be_displayed();

        assert_eq!(result, true)
    }

    fn response_with_stats_and_either_top_records_or_top_queries(
        for_top_records: bool,
    ) -> UiFinancialsResponse {
        UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 116688555,
                total_paid_payable_gwei: 235555554578,
                total_unpaid_receivable_gwei: 0,
                total_paid_receivable_gwei: 665557,
            }),
            query_results_opt: Some(if for_top_records {
                QueryResults {
                    payable_opt: Some(vec![
                        UiPayableAccount {
                            wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                            age_s: 5645405400,
                            balance_gwei: 68843325667,
                            pending_payable_hash_opt: None,
                        },
                        UiPayableAccount {
                            wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                            age_s: 150000,
                            balance_gwei: 8,
                            pending_payable_hash_opt: Some(
                                "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                                    .to_string(),
                            ),
                        },
                    ]),
                    receivable_opt: Some(vec![
                        UiReceivableAccount {
                            wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                            age_s: 22000,
                            balance_gwei: 2444533124512,
                        },
                        UiReceivableAccount {
                            wallet: "0x8bA50675e590b545D2128905b89039256Eaa24F6".to_string(),
                            age_s: 19000,
                            balance_gwei: -328123256546,
                        },
                    ]),
                }
            } else {
                QueryResults {
                    payable_opt: Some(vec![UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age_s: 150000,
                        balance_gwei: 8,
                        pending_payable_hash_opt: Some(
                            "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                                .to_string(),
                        ),
                    }]),
                    receivable_opt: None,
                }
            }),
        }
    }

    #[tokio::test]
    async fn financials_command_stats_and_top_records_default_units_as_masq() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(true);
        let args = slice_of_strs_to_vec_of_strings(&["financials", "--top", "123"]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 123,
                        ordered_by: TopRecordsOrdering::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stream_handles.stdout_all_in_one(),
                   "\
                \n\
                Financial status totals in MASQ\n\
                \n\
                Unpaid and pending payable:       0.11\n\
                Paid payable:                     235.55\n\
                Unpaid receivable:                < 0.01\n\
                Paid receivable:                  < 0.01\n\
                \n\
                \n\
                \n\
                Up to 123 top accounts\n\
                \n\
                Payable\n\
                \n\
                #   Wallet                                       Age [s]         Balance [MASQ]   Pending tx                                                        \n\
                1   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   5,645,405,400   68.84            None                                                              \n\
                2   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000         < 0.01           0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Receivable\n\
                \n\
                #   Wallet                                       Age [s]   Balance [MASQ]\n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   22,000    2,444.53      \n\
                2   0x8bA50675e590b545D2128905b89039256Eaa24F6   19,000    -328.12       \n");
        stream_handles.assert_empty_stderr()
    }

    #[tokio::test]
    async fn financials_command_stats_and_custom_query_demanded_default_units_as_masq() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(false);
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--payable",
            "0-350000|0.005-9",
            "--receivable",
            "5000-10000|0.003000000-5.600070000",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 0,
                            max_age_s: 350000,
                            min_amount_gwei: 5000000,
                            max_amount_gwei: 9000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 5000,
                            max_age_s: 10000,
                            min_amount_gwei: 3000000,
                            max_amount_gwei: 5600070000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stream_handles.stdout_all_in_one(),
                   "\
                \n\
                Financial status totals in MASQ\n\
                \n\
                Unpaid and pending payable:       0.11\n\
                Paid payable:                     235.55\n\
                Unpaid receivable:                < 0.01\n\
                Paid receivable:                  < 0.01\n\
                \n\
                \n\
                \n\
                Specific payable query: 0 - 350000 sec old, 0.005 - 9 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [MASQ]   Pending tx                                                        \n\
                1   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000   < 0.01           0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Specific receivable query: 5000 - 10000 sec old, 0.003 - 5.60007 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [MASQ]\n\
                \n\
                No records found\n"
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn financials_command_statistics_and_top_records_with_gwei_precision() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(true);
        let args = slice_of_strs_to_vec_of_strings(&["financials", "--top", "123", "--gwei"]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 123,
                        ordered_by: TopRecordsOrdering::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stream_handles.stdout_flushed_strings(),
                   vec!["\
                \n\
                Financial status totals in gwei\n\
                \n\
                Unpaid and pending payable:       116,688,555\n\
                Paid payable:                     235,555,554,578\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  665,557\n\
                \n\
                \n\
                \n\
                Up to 123 top accounts\n\
                \n\
                Payable\n\
                \n\
                #   Wallet                                       Age [s]         Balance [gwei]   Pending tx                                                        \n\
                1   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   5,645,405,400   68,843,325,667   None                                                              \n\
                2   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000         8                0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Receivable\n\
                \n\
                #   Wallet                                       Age [s]   Balance [gwei]   \n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   22,000    2,444,533,124,512\n\
                2   0x8bA50675e590b545D2128905b89039256Eaa24F6   19,000    -328,123,256,546 \n"]
        );
        assert_eq!(
            stream_handles.stderr_flushed_strings(),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn financials_command_statistics_and_custom_query_with_gwei_precision() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(false);
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--payable",
            "0-350000|0.005-9",
            "--receivable",
            "5000-10000|0.000004-0.4550",
            "--gwei",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 0,
                            max_age_s: 350000,
                            min_amount_gwei: 5000000,
                            max_amount_gwei: 9000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 5000,
                            max_age_s: 10000,
                            min_amount_gwei: 4000,
                            max_amount_gwei: 455000000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stream_handles.stdout_flushed_strings(), vec!["\
                \n\
                Financial status totals in gwei\n\
                \n\
                Unpaid and pending payable:       116,688,555\n\
                Paid payable:                     235,555,554,578\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  665,557\n\
                \n\
                \n\
                \n\
                Specific payable query: 0 - 350000 sec old, 0.005 - 9 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [gwei]   Pending tx                                                        \n\
                1   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000   8                0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Specific receivable query: 5000 - 10000 sec old, 0.000004 - 0.455 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [gwei]\n\
                \n\
                No records found\n"]);
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn custom_query_balance_range_can_be_shorthanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            query_results_opt: Some(QueryResults {
                payable_opt: Some(vec![UiPayableAccount {
                    wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                    age_s: 150000,
                    balance_gwei: 1200000000000,
                    pending_payable_hash_opt: Some(
                        "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                            .to_string(),
                    ),
                }]),
                receivable_opt: Some(vec![UiReceivableAccount {
                    wallet: "0x8bA50675e590b545D2128905b89039256Eaa24F6".to_string(),
                    age_s: 45700,
                    balance_gwei: 5050330000,
                }]),
            }),
        };
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--payable",
            "0-350000|5",
            "--receivable",
            "5000-10000|0.8",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 0,
                            max_age_s: 350_000,
                            min_amount_gwei: 5_000_000_000,
                            max_amount_gwei: i64::MAX as u64
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 5000,
                            max_age_s: 10_000,
                            min_amount_gwei: 800_000_000,
                            max_amount_gwei: i64::MAX
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stream_handles.stdout_flushed_strings(),
                   vec!["\n\
            Specific payable query: 0 - 350000 sec old, 5 - ∞ MASQ\n\
            \n\
            #   Wallet                                       Age [s]   Balance [MASQ]   Pending tx                                                        \n\
            1   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000   1,200.00         0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
            \n\
            \n\
            \n\
            Specific receivable query: 5000 - 10000 sec old, 0.8 - ∞ MASQ\n\
            \n\
            #   Wallet                                       Age [s]   Balance [MASQ]\n\
            1   0x8bA50675e590b545D2128905b89039256Eaa24F6   45,700    5.05          \n".to_string()]
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn financials_command_no_records_found_with_stats_and_top_records() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 116688,
                total_paid_payable_gwei: 55555,
                total_unpaid_receivable_gwei: 221144,
                total_paid_receivable_gwei: 66555,
            }),
            query_results_opt: Some(QueryResults {
                payable_opt: Some(vec![]),
                receivable_opt: Some(vec![]),
            }),
        };
        let args = slice_of_strs_to_vec_of_strings(&["financials", "--top", "10"]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 10,
                        ordered_by: TopRecordsOrdering::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_flushed_strings(),
            vec!["\
|
|Financial status totals in MASQ
|
|Unpaid and pending payable:       < 0.01
|Paid payable:                     < 0.01
|Unpaid receivable:                < 0.01
|Paid receivable:                  < 0.01
|
|
|
|Up to 10 top accounts
|
|Payable
|
|#   Wallet                                       Age [s]   Balance [MASQ]   Pending tx
|
|No records found
|
|
|
|Receivable
|
|#   Wallet                                       Age [s]   Balance [MASQ]
|
|No records found\n"
                .lines()
                .map(|line| format!("{}\n", line.strip_prefix("|").unwrap()))
                .collect::<String>()]
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn financials_command_no_records_found_with_stats_and_custom_query() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 116688,
                total_paid_payable_gwei: 55555,
                total_unpaid_receivable_gwei: 221144,
                total_paid_receivable_gwei: 66555,
            }),
            query_results_opt: Some(QueryResults {
                payable_opt: None,
                receivable_opt: None,
            }),
        };
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--payable",
            "0-400000|355-6000",
            "--receivable",
            "40000-80000|111-10000",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 0,
                            max_age_s: 400000,
                            min_amount_gwei: 355000000000,
                            max_amount_gwei: 6000000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 40000,
                            max_age_s: 80000,
                            min_amount_gwei: 111000000000,
                            max_amount_gwei: 10000000000000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_flushed_strings(),
            vec!["\
|
|Financial status totals in MASQ
|
|Unpaid and pending payable:       < 0.01
|Paid payable:                     < 0.01
|Unpaid receivable:                < 0.01
|Paid receivable:                  < 0.01
|
|
|
|Specific payable query: 0 - 400000 sec old, 355 - 6000 MASQ
|
|#   Wallet                                       Age [s]   Balance [MASQ]   Pending tx
|
|No records found
|
|
|
|Specific receivable query: 40000 - 80000 sec old, 111 - 10000 MASQ
|
|#   Wallet                                       Age [s]   Balance [MASQ]
|
|No records found"
                .lines()
                .map(|line| format!("{}\n", line.strip_prefix("|").unwrap()))
                .collect::<String>()]
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn financials_command_only_top_records_demanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            query_results_opt: Some(QueryResults {
                payable_opt: Some(vec![
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age_s: 5405400,
                        balance_gwei: 644000000,
                        pending_payable_hash_opt: Some(
                            "0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638"
                                .to_string(),
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0xEA674fdac714fd979de3EdF0F56AA9716B198ec8".to_string(),
                        age_s: 28120444,
                        balance_gwei: 97524120,
                        pending_payable_hash_opt: None,
                    },
                ]),
                receivable_opt: Some(vec![
                    UiReceivableAccount {
                        wallet: "0xaa22968a5263f165F014d3F21A443f10a116EDe0".to_string(),
                        age_s: 566668,
                        balance_gwei: 550,
                    },
                    UiReceivableAccount {
                        wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                        age_s: 11111111,
                        balance_gwei: -4551012,
                    },
                ]),
            }),
        };
        let args = slice_of_strs_to_vec_of_strings(&["financials", "--no-stats", "--top", "7"]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 7,
                        ordered_by: TopRecordsOrdering::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_flushed_strings(),
            vec!["\n\
                Up to 7 top accounts\n\
                \n\
                Payable\n\
                \n\
                #   Wallet                                       Age [s]      Balance [MASQ]   Pending tx                                                        \n\
                1   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   5,405,400    0.64             0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638\n\
                2   0xEA674fdac714fd979de3EdF0F56AA9716B198ec8   28,120,444   0.09             None                                                              \n\
                \n\
                \n\
                \n\
                Receivable\n\
                \n\
                #   Wallet                                       Age [s]      Balance [MASQ]\n\
                1   0xaa22968a5263f165F014d3F21A443f10a116EDe0   566,668      < 0.01        \n\
                2   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   11,111,111   -0.01 < x < 0 \n".to_string()]
        );
        stream_handles.assert_empty_stderr()
    }

    #[tokio::test]
    async fn financials_command_only_payable_demanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            query_results_opt: Some(QueryResults {
                payable_opt: Some(vec![
                    UiPayableAccount {
                        wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                        age_s: 4445,
                        balance_gwei: 3862654858938090,
                        pending_payable_hash_opt: Some(
                            "0x5fe272ed1e941cc05fbd624ec4b1546cd03c25d53e24ba2c18b11feb83cd4581"
                                .to_string(),
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age_s: 70000,
                        balance_gwei: 708090,
                        pending_payable_hash_opt: None,
                    },
                    UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age_s: 6089909,
                        balance_gwei: 66658,
                        pending_payable_hash_opt: None,
                    },
                ]),
                receivable_opt: None,
            }),
        };
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--payable",
            "3000-40000|88-1000",
            "--no-stats",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 3000,
                            max_age_s: 40000,
                            min_amount_gwei: 88000000000,
                            max_amount_gwei: 1000000000000
                        }),
                        receivable_opt: None
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_all_in_one(),
            "\n\
                Specific payable query: 3000 - 40000 sec old, 88 - 1000 MASQ\n\
                \n\
                #   Wallet                                       Age [s]     Balance [MASQ]   Pending tx                                                        \n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   4,445       3,862,654.85     0x5fe272ed1e941cc05fbd624ec4b1546cd03c25d53e24ba2c18b11feb83cd4581\n\
                2   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   70,000      < 0.01           None                                                              \n\
                3   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   6,089,909   < 0.01           None                                                              \n"
        );
        stream_handles.assert_empty_stderr()
    }

    #[tokio::test]
    async fn financials_command_only_receivable_demanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            query_results_opt: Some(QueryResults {
                payable_opt: None,
                receivable_opt: Some(vec![
                    UiReceivableAccount {
                        wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                        age_s: 4445,
                        balance_gwei: 9898999888,
                    },
                    UiReceivableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age_s: 70000,
                        balance_gwei: 708090,
                    },
                    UiReceivableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age_s: 6089909,
                        balance_gwei: 66658,
                    },
                ]),
            }),
        };
        let args = slice_of_strs_to_vec_of_strings(&[
            "financials",
            "--no-stats",
            "--receivable",
            "3000-40000|66-980",
            "--gwei",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: None,
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 3000,
                            max_age_s: 40000,
                            min_amount_gwei: 66000000000,
                            max_amount_gwei: 980000000000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_all_in_one(),
            "\n\
                Specific receivable query: 3000 - 40000 sec old, 66 - 980 MASQ\n\
                \n\
                #   Wallet                                       Age [s]     Balance [gwei]\n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   4,445       9,898,999,888 \n\
                2   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   70,000      708,090       \n\
                3   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   6,089,909   66,658        \n"
        );
        stream_handles.assert_empty_stderr()
    }

    #[tokio::test]
    async fn financials_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let args = &["financials".to_string()];
        let subject = FinancialsCommand::new(args).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_flushed_writings_to_finish().await;
        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: None,
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        stream_handles.assert_empty_stdout();
        assert_eq!(
            stream_handles.stderr_all_in_one(),
            "Financials retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
