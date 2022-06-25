// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use masq_lib::messages::{
    CustomQueries, RangeQuery, UiFinancialsRequest, UiFinancialsResponse, UiPayableAccount,
    UiReceivableAccount,
};
use masq_lib::shared_schema::common_validators::{validate_non_zero_usize, validate_two_ranges};
use masq_lib::short_writeln;
use masq_lib::utils::{plus, ExpectValue};
use std::cell::RefCell;
use std::fmt::Display;
use std::io::Write;
use std::str::FromStr;
use thousands::Separable;

const FINANCIALS_SUBCOMMAND_ABOUT: &str =
    "Displays financial statistics of this Node. Only valid if Node is already running.";

//TODO don't forget to return back here
const TOP_ARG_HELP: &str = "blah";

const PAYABLE_ARG_HELP: &str = "blah";

const RECEIVABLE_ARG_HELP: &str = "blah";

const NO_STATS_ARG_HELP: &str = "blah";

const WALLET_ADDRESS_LENGTH: usize = 42;

#[derive(Debug, Clone)]
pub struct FinancialsCommand {
    stats_required: bool,
    top_records_opt: Option<usize>,
    custom_queries_opt: Option<CustomQueries>,
}

pub fn financials_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("financials")
        .about(FINANCIALS_SUBCOMMAND_ABOUT)
        .arg(
            Arg::with_name("top")
                .help(TOP_ARG_HELP)
                .value_name("TOP")
                .long("top")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .validator(validate_non_zero_usize),
        )
        .arg(
            Arg::with_name("payable")
                .help(PAYABLE_ARG_HELP)
                .value_name("PAYABLE")
                .long("payable")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .validator(validate_two_ranges::<u128>),
        )
        .arg(
            Arg::with_name("receivable")
                .help(RECEIVABLE_ARG_HELP)
                .value_name("PAYABLE")
                .long("receivable")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .validator(validate_two_ranges::<i128>),
        )
        .arg(
            Arg::with_name("no-stats")
                .help(NO_STATS_ARG_HELP)
                .value_name("NO-STATS")
                .long("no-stats")
                .required(false)
                .case_insensitive(false)
                .takes_value(false),
        )
}

impl Command for FinancialsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiFinancialsRequest {
            stats_required: self.stats_required,
            top_records_opt: self.top_records_opt,
            custom_queries_opt: self.custom_queries_opt.clone(),
        };
        let output: Result<UiFinancialsResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(response) => {
                let stdout = context.stdout();
                if let Some(stats) = response.stats_opt {
                    Self::financial_status_totals_header(stdout);
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
                if let Some(top_records) = response.top_records_opt {
                    Self::double_blank_line(stdout);
                    self.main_header_to_tops(stdout, "payable");
                    self.render_payable(stdout, top_records.payable);
                    Self::double_blank_line(stdout);
                    self.main_header_to_tops(stdout, "receivable");
                    self.render_receivable(stdout, top_records.receivable)
                }
                if let Some(custom_query) = response.custom_query_records_opt {
                    if let Some(payable_accounts) = custom_query.payable_opt {
                        Self::double_blank_line(stdout);
                        Self::custom_query_header(
                            stdout,
                            "Payable",
                            self.custom_queries_opt
                                .as_ref()
                                .expectv("custom query")
                                .payable_opt
                                .as_ref()
                                .expectv("payable custom query"),
                        );
                        self.render_payable(stdout, payable_accounts)
                    }
                    if let Some(receivable_accounts) = custom_query.receivable_opt {
                        Self::double_blank_line(stdout);
                        Self::custom_query_header(
                            stdout,
                            "Receivable",
                            self.custom_queries_opt
                                .as_ref()
                                .expectv("custom query")
                                .receivable_opt
                                .as_ref()
                                .expectv("receivable custom query"),
                        );
                        self.render_receivable(stdout, receivable_accounts)
                    }
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
        let stats_required = !matches.is_present("no-stats");
        let top_records_opt = matches.value_of("top").map(|str| {
            str.parse::<usize>()
                .expect("top records count not properly required")
        });
        let custom_payable_opt = Self::parse_range_query(&matches, "payable");
        let custom_receivable_opt = Self::parse_range_query(&matches, "receivable");
        Ok(Self {
            stats_required,
            top_records_opt,
            custom_queries_opt: match (&custom_payable_opt, &custom_receivable_opt) {
                (None, None) => None,
                _ => Some(CustomQueries {
                    payable_opt: custom_payable_opt,
                    receivable_opt: custom_receivable_opt,
                }),
            },
        })
    }

    fn parse<N: FromStr>(str_val: &str, name: &str) -> N {
        str::parse::<N>(str_val).unwrap_or_else(|_| panic!("{} non properly required", name))
    }

    fn parse_range_query<T: FromStr>(
        matches: &ArgMatches,
        parameter_name: &str,
    ) -> Option<RangeQuery<T>> {
        matches.value_of(parameter_name).map(|double| {
            let params = double
                .split("|")
                .map(|half| half.rsplit_once("-").expect("blah"))
                .fold(vec![], |acc, current| plus(plus(acc, current.0), current.1));
            RangeQuery {
                min_age: Self::parse(params[0], "min_age"),
                max_age: Self::parse(params[1], "max_age"),
                min_amount: Self::parse::<T>(params[2], "min_amount"),
                max_amount: Self::parse::<T>(params[3], "max_amount"),
            }
        })
    }

    fn financial_status_totals_header(stdout: &mut dyn Write){
        short_writeln!(stdout, "Financial status totals in Wei");
        short_writeln!(stdout, "{}","=".repeat(30));
    }

    fn main_header_to_tops(&self, stdout: &mut dyn Write, distinguished: &str) {
        let requested_count = self.top_records_opt.expectv("requested count");
        short_writeln!(
            stdout,
            "Top {} accounts in {}\n{}",
            requested_count,
            distinguished,
            "=".repeat(17 + distinguished.len() + requested_count.to_string().len())
        )
    }

    fn width_precise_calculation(headers: &[&str], accounts: &[&dyn WidthInfo]) -> Vec<usize> {
        let headers_widths = headers
            .iter()
            .skip(1)
            .map(|word| word.len() + 2)
            .collect::<Vec<usize>>();
        let values_widths = Self::figure_out_max_widths(accounts);
        Self::yield_bigger_values_from_vecs(headers_widths.len(), headers_widths, values_widths)
    }

    fn headers_underscore(optimal_widths: &[usize]) -> String {
        "-".repeat(
            optimal_widths.iter().fold(0, |acc, width| acc + width)
                + WALLET_ADDRESS_LENGTH
                + optimal_widths.len()
                + 2,
        )
    }

    fn render_payable(&self, stdout: &mut dyn Write, accounts: Vec<UiPayableAccount>) {
        let headers = &["Wallet", "Age [s]", "Balance [Wei]", "Tx rowid"];
        let optimal_widths = Self::width_precise_calculation(
            headers,
            &accounts
                .iter()
                .map(|each| each as &dyn WidthInfo)
                .collect::<Vec<&dyn WidthInfo>>(),
        );
        short_writeln!(
            stdout,
            "|{:^wallet_width$}|{:^age_width$}|{:^balance_width$}|{:^rowid_width$}|\n{}",
            headers[0],
            headers[1],
            headers[2],
            headers[3],
            Self::headers_underscore(&optimal_widths),
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = optimal_widths[0],
            balance_width = optimal_widths[1],
            rowid_width = optimal_widths[2]
        );
        accounts
            .iter()
            .for_each(|account| Self::render_single_payable(stdout, account, &optimal_widths));
    }

    fn render_single_payable(
        stdout: &mut dyn Write,
        account: &UiPayableAccount,
        width_config: &[usize],
    ) {
        short_writeln!(
            stdout,
            "|{:wallet_width$}|{:>age_width$}|{:>balance_width$}|{:>rowid_width$}|",
            account.wallet,
            account.age.separate_with_commas(),
            account.amount.separate_with_commas(),
            if let Some(rowid) = account.pending_payable_rowid_opt {
                rowid.to_string().separate_with_commas()
            } else {
                "None".to_string()
            },
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = width_config[0],
            balance_width = width_config[1],
            rowid_width = width_config[2]
        )
    }

    fn render_receivable(&self, stdout: &mut dyn Write, accounts: Vec<UiReceivableAccount>) {
        let headers = &["Wallet", "Age [s]", "Balance [Wei]"];
        let optimal_widths = Self::width_precise_calculation(
            headers,
            &accounts
                .iter()
                .map(|each| each as &dyn WidthInfo)
                .collect::<Vec<&dyn WidthInfo>>(),
        );
        short_writeln!(
            stdout,
            "|{:^wallet_width$}|{:^age_width$}|{:^balance_width$}|\n{}",
            headers[0],
            headers[1],
            headers[2],
            Self::headers_underscore(&optimal_widths),
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = optimal_widths[0],
            balance_width = optimal_widths[1],
        );
        accounts
            .iter()
            .for_each(|account| Self::render_single_receivable(stdout, account, &optimal_widths));
    }

    fn render_single_receivable(
        stdout: &mut dyn Write,
        account: &UiReceivableAccount,
        width_config: &[usize],
    ) {
        short_writeln!(
            stdout,
            "|{:wallet_width$}|{:>age_width$}|{:>balance_width$}|",
            account.wallet,
            account.age.separate_with_commas(),
            account.amount.separate_with_commas(),
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = width_config[0],
            balance_width = width_config[1],
        )
    }

    fn custom_query_header<N: Display>(
        stdout: &mut dyn Write,
        distinguished: &str,
        range_query: &RangeQuery<N>,
    ) {
        short_writeln!(
            stdout,
            "{} query with parameters: {}-{} s and {}-{} Wei\n{}",
            distinguished,
            range_query.min_age,
            range_query.max_age,
            range_query.min_amount,
            range_query.max_amount,
            "=".repeat(
                37 + distinguished.len()
                    + range_query.min_age.to_string().len()
                    + range_query.max_age.to_string().len()
                    + range_query.min_amount.to_string().len()
                    + range_query.max_amount.to_string().len()
            )
        )
    }

    fn figure_out_max_widths(records: &[&dyn WidthInfo]) -> Vec<usize> {
        let cell_count = records[0].widths().len();
        let init = vec![0_usize; cell_count];
        records.iter().fold(init, |acc, record| {
            let cells = record.widths();
            Self::yield_bigger_values_from_vecs(cell_count, acc, cells)
        })
    }

    fn yield_bigger_values_from_vecs(
        cell_count: usize,
        first: Vec<usize>,
        second: Vec<usize>,
    ) -> Vec<usize> {
        fn yield_bigger(a: usize, b: usize) -> usize {
            if a > b {
                a
            } else {
                b
            }
        }
        (0..cell_count).fold(vec![], |acc_inner, idx| {
            plus(acc_inner, yield_bigger(first[idx], second[idx]))
        })
    }

    fn count_length_with_comma_separators<N: Display>(number: N) -> usize {
        let gross_length = number.to_string().len();
        let triple_chars = gross_length / 3;
        let possible_reminder = gross_length % 3;
        if possible_reminder == 0 {
            triple_chars * 3 + triple_chars - 1
        } else {
            triple_chars * 3 + possible_reminder + triple_chars
        }
    }

    fn double_blank_line(stdout: &mut dyn Write) {
        short_writeln!(stdout, "\n")
    }
}

trait WidthInfo {
    fn widths(&self) -> Vec<usize>;
}

impl WidthInfo for UiPayableAccount {
    fn widths(&self) -> Vec<usize> {
        vec![
            FinancialsCommand::count_length_with_comma_separators(self.age),
            FinancialsCommand::count_length_with_comma_separators(self.amount),
            FinancialsCommand::count_length_with_comma_separators(
                if let Some(pending_payable_rowid) = self.pending_payable_rowid_opt {
                    FinancialsCommand::count_length_with_comma_separators(pending_payable_rowid)
                } else {
                    0
                },
            ),
        ]
    }
}

impl WidthInfo for UiReceivableAccount {
    fn widths(&self) -> Vec<usize> {
        vec![
            FinancialsCommand::count_length_with_comma_separators(self.age),
            FinancialsCommand::count_length_with_comma_separators(self.amount),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::test_utils::mocks::CommandContextMock;
    use indoc::indoc;
    use masq_lib::messages::{
        CustomQueryResult, FinancialStatistics, FirmQueryResult, ToMessageBody,
        UiFinancialsResponse, UiPayableAccount, UiReceivableAccount,
    };
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriterInner;
    use masq_lib::ui_gateway::MessageBody;
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
    fn command_factory_default_command() {
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
            .make(&array_of_borrows_to_vec(&[
                "financials",
                "--top",
                "20",
                "--no-stats",
            ]))
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
                "--top",
                "10",
                "--payable",
                "200-450|48000000111-158000008000",
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
        let subject = FinancialsCommand::new(args).unwrap();

        let result = subject.execute(&mut context);

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
            stdout_arc.lock().unwrap().get_string(),
            "\
                Financial status totals in Wei\n\
                ==============================\n\
                Unpaid and pending payable:       116688\n\
                Paid payable:                     55555\n\
                Unpaid receivable:                221144\n\
                Paid receivable:                  66555\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    struct TestAccount {
        a: usize,
        b: usize,
        c: usize,
    }

    impl WidthInfo for TestAccount {
        fn widths(&self) -> Vec<usize> {
            vec![self.a, self.b, self.c]
        }
    }

    #[test]
    fn figure_out_max_widths_works() {
        let vec_of_accounts = vec![
            TestAccount { a: 5, b: 2, c: 3 },
            TestAccount { a: 4, b: 6, c: 2 },
            TestAccount { a: 1, b: 4, c: 7 },
        ];
        let to_inspect = vec_of_accounts
            .iter()
            .map(|each| each as &dyn WidthInfo)
            .collect::<Vec<&dyn WidthInfo>>();

        let result = FinancialsCommand::figure_out_max_widths(&to_inspect);

        assert_eq!(result, vec![5, 6, 7])
    }

    #[test]
    fn count_length_with_comma_separators_works_for_exact_triples() {
        let number = 200_560_800;

        let result = FinancialsCommand::count_length_with_comma_separators(number);

        assert_eq!(result, 11)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_incomplete_triples() {
        let number = 12_200_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number);

        assert_eq!(result, 14)
    }

    #[test]
    fn financials_command_everything_demanded_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(FinancialStatistics {
                total_unpaid_and_pending_payable: 116688,
                total_paid_payable: 55555,
                total_unpaid_receivable: 221144,
                total_paid_receivable: 66555,
            }),
            top_records_opt: Some(FirmQueryResult {
                payable: vec![
                    UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 150000,
                        amount: 8456582898,
                        pending_payable_rowid_opt: Some(5),
                    },
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 5645405400,
                        amount: 884332566,
                        pending_payable_rowid_opt: None,
                    },
                ],
                receivable: vec![UiReceivableAccount {
                    wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                    age: 22000,
                    amount: 12444551012,
                }],
            }),
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: Some(vec![UiPayableAccount {
                    wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                    age: 150000,
                    amount: 8456582898,
                    pending_payable_rowid_opt: Some(5),
                }]),
                receivable_opt: None,
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--top",
            "123",
            "--payable",
            "0-350000|5000000-9000000000",
            "--receivable",
            "5000-10000|3000000-5600070000",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: true,
                    top_records_opt: Some(123),
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age: 0,
                            max_age: 350000,
                            min_amount: 5000000,
                            max_amount: 9000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age: 5000,
                            max_age: 10000,
                            min_amount: 3000000,
                            max_amount: 5600070000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            indoc!("
                Financial status totals in Wei
                ==============================
                Unpaid and pending payable:       116688
                Paid payable:                     55555
                Unpaid receivable:                221144
                Paid receivable:                  66555


                Top 123 accounts in payable
                ===========================
                |                  Wallet                  |   Age [s]   | Balance [Wei] | Tx rowid |
                -------------------------------------------------------------------------------------
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|      150,000|  8,456,582,898|         5|
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|    884,332,566|      None|


                Top 123 accounts in receivable
                ==============================
                |                  Wallet                  | Age [s] | Balance [Wei] |
                ----------------------------------------------------------------------
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|   22,000| 12,444,551,012|


                Payable query with parameters: 0-350000 s and 5000000-9000000000 Wei
                ====================================================================
                |                  Wallet                  | Age [s] | Balance [Wei] | Tx rowid |
                ---------------------------------------------------------------------------------
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|  150,000|  8,456,582,898|         5|


                Receivable query with parameters: 5000-10000 s and 3000000-5600070000 Wei
                =========================================================================
                |                  Wallet                  |    Age [s]  | Balance [Wei] | Tx rowid |
                -------------------------------------------------------------------------------------
                                                   No result
            "
        ));
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        todo!("rewrite and finish the test")
    }

    #[test]
    fn financials_command_only_top_records_demanded_happy_path() {
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
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--no-stats",
            "--receivable",
            "3000-4000|8866-10000000",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = subject.execute(&mut context);

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
        todo!("rewrite and finish the test")
    }

    #[test]
    fn financials_command_only_payable_demanded_happy_path() {
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
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--no-stats",
            "--receivable",
            "3000-4000|8866-10000000",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = subject.execute(&mut context);

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
        todo!("rewrite and finish the test")
    }

    #[test]
    fn financials_command_only_receivable_demanded_happy_path() {
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
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--no-stats",
            "--receivable",
            "3000-4000|8866-10000000",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = subject.execute(&mut context);

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
        todo!("rewrite and finish the test")
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
        let subject = FinancialsCommand::new(args).unwrap();

        let result = subject.execute(&mut context);

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
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Financials retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
