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
use std::fmt::Display;
use std::io::Write;
use std::str::FromStr;
use thousands::Separable;

const FINANCIALS_SUBCOMMAND_ABOUT: &str =
    "Displays financial statistics of this Node. Only valid if Node is already running.";
const TOP_ARG_HELP: &str = "Returns the first N records from both payable and receivable";
const PAYABLE_ARG_HELP: &str = "Allows to configure a detailed query for payable with ranges about the age and balance of records. The required format of the query's input is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const RECEIVABLE_ARG_HELP: &str = "Allows to configure a detailed query for receivable with ranges about the age and balance of records. The required format of the query's input is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const NO_STATS_ARG_HELP: &str = "Disables the default statistics about totals of paid and unpaid money from both your debtors and creditors";
const WALLET_ADDRESS_LENGTH: usize = 42;
const PAYABLE_HEADERS: &[&str] = &["Wallet", "Age [s]", "Balance [Wei]", "Pending tx"];
const RECEIVABLE_HEADERS: &[&str] = &["Wallet", "Age [s]", "Balance [Wei]"];

#[derive(Debug, Clone)]
pub struct FinancialsCommand {
    stats_required: bool,
    top_records_opt: Option<u16>,
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
                        &stats
                            .total_unpaid_and_pending_payable
                            .separate_with_commas(),
                    );
                    dump_parameter_line(
                        stdout,
                        "Paid payable:",
                        &stats.total_paid_payable.separate_with_commas(),
                    );
                    dump_parameter_line(
                        stdout,
                        "Unpaid receivable:",
                        &stats.total_unpaid_receivable.separate_with_commas(),
                    );
                    dump_parameter_line(
                        stdout,
                        "Paid receivable:",
                        &stats.total_paid_receivable.separate_with_commas(),
                    );
                }
                if let Some(top_records) = response.top_records_opt {
                    if let Some(payable) = top_records.payable_opt {
                        self.main_header_to_tops(stdout, "payable");
                        self.render_payable(stdout, payable);
                    } else {
                        self.main_header_to_tops(stdout, "payable");
                        Self::no_records_found(stdout, PAYABLE_HEADERS, Self::write_payable_headers)
                    }
                    if let Some(receivable) = top_records.receivable_opt {
                        self.main_header_to_tops(stdout, "receivable");
                        self.render_receivable(stdout, receivable)
                    } else {
                        self.main_header_to_tops(stdout, "receivable");
                        Self::no_records_found(
                            stdout,
                            RECEIVABLE_HEADERS,
                            Self::write_receivable_headers,
                        )
                    }
                }
                if let Some(custom_query) = response.custom_query_records_opt {
                    if let Some(payable_accounts) = custom_query.payable_opt {
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
                    } else if self
                        .custom_queries_opt
                        .as_ref()
                        .expectv("custom query input")
                        .payable_opt
                        .is_some()
                    {
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
                        Self::no_records_found(stdout, PAYABLE_HEADERS, Self::write_payable_headers)
                    }
                    if let Some(receivable_accounts) = custom_query.receivable_opt {
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
                    } else if self
                        .custom_queries_opt
                        .as_ref()
                        .expectv("custom query input")
                        .receivable_opt
                        .is_some()
                    {
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
                        Self::no_records_found(
                            stdout,
                            RECEIVABLE_HEADERS,
                            Self::write_receivable_headers,
                        )
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
            str.parse::<u16>()
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

    fn financial_status_totals_header(stdout: &mut dyn Write) {
        short_writeln!(stdout, "Financial status totals in Wei");
        short_writeln!(stdout, "{}", "=".repeat(30));
    }

    fn main_header_to_tops(&self, stdout: &mut dyn Write, distinguished: &str) {
        Self::double_blank_line(stdout);
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

    fn full_length(optimal_widths: &[usize]) -> usize {
        optimal_widths.iter().fold(0, |acc, width| acc + width)
            + WALLET_ADDRESS_LENGTH
            + optimal_widths.len()
            + 2
    }

    fn headers_underscore(optimal_widths: &[usize]) -> String {
        "-".repeat(Self::full_length(optimal_widths))
    }

    fn render_payable(&self, stdout: &mut dyn Write, accounts: Vec<UiPayableAccount>) {
        let headers = PAYABLE_HEADERS;
        let optimal_widths = Self::width_precise_calculation(
            headers,
            &accounts
                .iter()
                .map(|each| each as &dyn WidthInfo)
                .collect::<Vec<&dyn WidthInfo>>(),
        );
        Self::write_payable_headers(stdout, headers, &optimal_widths);
        accounts
            .iter()
            .for_each(|account| Self::render_single_payable(stdout, account, &optimal_widths));
    }

    fn write_payable_headers(stdout: &mut dyn Write, headers: &[&str], optimal_widths: &[usize]) {
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
        )
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
            account.balance.separate_with_commas(),
            if let Some(hash) = &account.pending_payable_hash_opt {
                hash.as_str()
            } else {
                "None"
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
        Self::write_receivable_headers(stdout, RECEIVABLE_HEADERS, &optimal_widths);
        accounts
            .iter()
            .for_each(|account| Self::render_single_receivable(stdout, account, &optimal_widths));
    }

    fn write_receivable_headers(
        stdout: &mut dyn Write,
        headers: &[&str],
        optimal_widths: &[usize],
    ) {
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
            account.balance.separate_with_commas(),
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
        Self::double_blank_line(stdout);
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

    fn no_records_found<F>(stdout: &mut dyn Write, headers: &[&str], write_headers: F)
    where
        F: Fn(&mut dyn Write, &[&str], &[usize]),
    {
        let headers_widths = headers
            .iter()
            .skip(1)
            .map(|word| word.len() + 2)
            .collect::<Vec<usize>>();
        let full_length = Self::full_length(&headers_widths);
        write_headers(stdout, headers, &headers_widths);
        short_writeln!(
            stdout,
            "{:^width$}",
            "No records found",
            width = full_length
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

    fn count_length_with_comma_separators<N: Display>(value: N) -> usize {
        let gross_length = value.to_string().len();
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
            FinancialsCommand::count_length_with_comma_separators(self.balance),
            if let Some(transaction_hash) = &self.pending_payable_hash_opt {
                transaction_hash.len()
            } else {
                0
            },
        ]
    }
}

impl WidthInfo for UiReceivableAccount {
    fn widths(&self) -> Vec<usize> {
        vec![
            FinancialsCommand::count_length_with_comma_separators(self.age),
            FinancialsCommand::count_length_with_comma_separators(self.balance),
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
    use masq_lib::messages::{
        CustomQueryResult, FirmQueryResult, ToMessageBody, UiFinancialStatistics,
        UiFinancialsResponse, UiPayableAccount, UiReceivableAccount,
    };
    use masq_lib::utils::array_of_borrows_to_vec;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            FINANCIALS_SUBCOMMAND_ABOUT,
            "Displays financial statistics of this Node. Only valid if Node is already running."
        );
        assert_eq!(
            TOP_ARG_HELP,
            "Returns the first N records from both payable and receivable"
        );
        assert_eq!(PAYABLE_ARG_HELP,"Allows to configure a detailed query for payable with ranges about the age and balance of records. The required format of the query's input is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>");
        assert_eq!(RECEIVABLE_ARG_HELP,"Allows to configure a detailed query for receivable with ranges about the age and balance of records. The required format of the query's input is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>");
        assert_eq!(NO_STATS_ARG_HELP,"Disables the default statistics about totals of paid and unpaid money from both your debtors and creditors");
        assert_eq!(WALLET_ADDRESS_LENGTH, 42);
        assert_eq!(
            PAYABLE_HEADERS,
            &["Wallet", "Age [s]", "Balance [Wei]", "Pending tx"]
        );
        assert_eq!(RECEIVABLE_HEADERS, &["Wallet", "Age [s]", "Balance [Wei]"]);
    }

    #[test]
    fn command_factory_default_command() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
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
                payable_opt: None,
                receivable_opt: None,
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
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable: 0,
                total_paid_payable: 1111,
                total_unpaid_receivable: 2222,
                total_paid_receivable: 3333,
            }),
            top_records_opt: Some(FirmQueryResult {
                payable_opt: None,
                receivable_opt: None,
            }),
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: None,
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
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable: 116688,
                total_paid_payable: 55555458897001,
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
                Unpaid and pending payable:       116,688\n\
                Paid payable:                     55,555,458,897,001\n\
                Unpaid receivable:                221,144\n\
                Paid receivable:                  66,555\n"
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
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable: 116688555,
                total_paid_payable: 555554578,
                total_unpaid_receivable: 4572221144,
                total_paid_receivable: 665557879787845,
            }),
            top_records_opt: Some(FirmQueryResult {
                payable_opt: Some(vec![
                    UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 150000,
                        balance: 8456582898,
                        pending_payable_hash_opt: Some(
                            "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                                .to_string(),
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 5645405400,
                        balance: 884332566,
                        pending_payable_hash_opt: None,
                    },
                ]),
                receivable_opt: Some(vec![UiReceivableAccount {
                    wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                    age: 22000,
                    balance: 12444551012,
                }]),
            }),
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: Some(vec![UiPayableAccount {
                    wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                    age: 150000,
                    balance: 8456582898,
                    pending_payable_hash_opt: Some(
                        "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                            .to_string(),
                    ),
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
        assert_eq!(stdout_arc.lock().unwrap().get_string(), {
            let main_text_block: &str = "\
                Financial status totals in Wei\n\
                ==============================\n\
                Unpaid and pending payable:       116,688,555\n\
                Paid payable:                     555,554,578\n\
                Unpaid receivable:                4,572,221,144\n\
                Paid receivable:                  665,557,879,787,845\n\
                \n\
                \n\
                Top 123 accounts in payable\n\
                ===========================\n\
                |                  Wallet                  |   Age [s]   | Balance [Wei] |                            Pending tx                            |\n\
                ---------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|      150,000|  8,456,582,898|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|    884,332,566|                                                              None|\n\
                \n\
                \n\
                Top 123 accounts in receivable\n\
                ==============================\n\
                |                  Wallet                  | Age [s] | Balance [Wei] |\n\
                ----------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|   22,000| 12,444,551,012|\n\
                \n\
                \n\
                Payable query with parameters: 0-350000 s and 5000000-9000000000 Wei\n\
                ====================================================================\n\
                |                  Wallet                  | Age [s] | Balance [Wei] |                            Pending tx                            |\n\
                -----------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|  150,000|  8,456,582,898|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                \n\
                \n\
                Receivable query with parameters: 5000-10000 s and 3000000-5600070000 Wei\n\
                =========================================================================\n\
                |                  Wallet                  | Age [s] | Balance [Wei] |\n\
                ----------------------------------------------------------------------\n";
            format!(
                "{}                           No records found                           \n",
                main_text_block
            )
        });
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_no_records_found_with_everything_demanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable: 116688,
                total_paid_payable: 55555,
                total_unpaid_receivable: 221144,
                total_paid_receivable: 66555,
            }),
            top_records_opt: Some(FirmQueryResult {
                payable_opt: None,
                receivable_opt: None,
            }),
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: None,
                receivable_opt: None,
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--top",
            "10",
            "--payable",
            "0-400000|5000000-60000000",
            "--receivable",
            "40000-80000|10000-1000000000",
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
                    top_records_opt: Some(10),
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age: 0,
                            max_age: 400000,
                            min_amount: 5000000,
                            max_amount: 60000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age: 40000,
                            max_age: 80000,
                            min_amount: 10000,
                            max_amount: 1000000000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\
|Financial status totals in Wei
|==============================
|Unpaid and pending payable:       116,688
|Paid payable:                     55,555
|Unpaid receivable:                221,144
|Paid receivable:                  66,555
|
|
|Top 10 accounts in payable
|==========================
||                  Wallet                  | Age [s] | Balance [Wei] | Pending tx |
|-----------------------------------------------------------------------------------
|                                 No records found                                  \n\
|
|
|Top 10 accounts in receivable
|=============================
||                  Wallet                  | Age [s] | Balance [Wei] |
|----------------------------------------------------------------------
|                           No records found                           \n\
|
|
|Payable query with parameters: 0-400000 s and 5000000-60000000 Wei
|==================================================================
||                  Wallet                  | Age [s] | Balance [Wei] | Pending tx |
|-----------------------------------------------------------------------------------
|                                 No records found                                  \n\
|
|
|Receivable query with parameters: 40000-80000 s and 10000-1000000000 Wei
|========================================================================
||                  Wallet                  | Age [s] | Balance [Wei] |
|----------------------------------------------------------------------
|                           No records found                           "
                .lines()
                .map(|line| format!("{}\n", line.strip_prefix("|").unwrap()))
                .collect::<String>()
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_only_top_records_demanded_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: Some(FirmQueryResult {
                payable_opt: Some(vec![UiPayableAccount {
                    wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                    age: 5645405400,
                    balance: 6000000,
                    pending_payable_hash_opt: Some(
                        "0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638"
                            .to_string(),
                    ),
                }]),
                receivable_opt: Some(vec![UiReceivableAccount {
                    wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                    age: 11111111,
                    balance: 12444551012,
                }]),
            }),
            custom_query_records_opt: None,
        };
        let args = array_of_borrows_to_vec(&["financials", "--no-stats", "--top", "7"]);
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
                    stats_required: false,
                    top_records_opt: Some(7),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
               "\n\
                \n\
                Top 7 accounts in payable\n\
                =========================\n\
                |                  Wallet                  |   Age [s]   | Balance [Wei] |                            Pending tx                            |\n\
                ---------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|      6,000,000|0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638|\n\
                \n\
                \n\
                Top 7 accounts in receivable\n\
                ============================\n\
                |                  Wallet                  | Age [s]  | Balance [Wei] |\n\
                -----------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|11,111,111| 12,444,551,012|\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_only_payable_demanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: Some(vec![
                    UiPayableAccount {
                        wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                        age: 4445,
                        balance: 9898999888,
                        pending_payable_hash_opt: Some(
                            "0x5fe272ed1e941cc05fbd624ec4b1546cd03c25d53e24ba2c18b11feb83cd4581"
                                .to_string(),
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 70000,
                        balance: 708090,
                        pending_payable_hash_opt: None,
                    },
                    UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 6089909,
                        balance: 66658,
                        pending_payable_hash_opt: None,
                    },
                ]),
                receivable_opt: None,
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--no-stats",
            "--payable",
            "3000-40000|8866-10000000",
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
                    stats_required: false,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age: 3000,
                            max_age: 40000,
                            min_amount: 8866,
                            max_amount: 10000000
                        }),
                        receivable_opt: None
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
               "\n\
                \n\
                Payable query with parameters: 3000-40000 s and 8866-10000000 Wei\n\
                =================================================================\n\
                |                  Wallet                  | Age [s] | Balance [Wei] |                            Pending tx                            |\n\
                -----------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|    4,445|  9,898,999,888|0x5fe272ed1e941cc05fbd624ec4b1546cd03c25d53e24ba2c18b11feb83cd4581|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|   70,000|        708,090|                                                              None|\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|6,089,909|         66,658|                                                              None|\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_only_receivable_demanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: None,
                receivable_opt: Some(vec![
                    UiReceivableAccount {
                        wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                        age: 4445,
                        balance: 9898999888,
                    },
                    UiReceivableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 70000,
                        balance: 708090,
                    },
                    UiReceivableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 6089909,
                        balance: 66658,
                    },
                ]),
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--no-stats",
            "--receivable",
            "3000-40000|8866-10000000",
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
                    stats_required: false,
                    top_records_opt: None,
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: None,
                        receivable_opt: Some(RangeQuery {
                            min_age: 3000,
                            max_age: 40000,
                            min_amount: 8866,
                            max_amount: 10000000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\n\
                \n\
                Receivable query with parameters: 3000-40000 s and 8866-10000000 Wei\n\
                ====================================================================\n\
                |                  Wallet                  | Age [s] | Balance [Wei] |\n\
                ----------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|    4,445|  9,898,999,888|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|   70,000|        708,090|\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|6,089,909|         66,658|\n"
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
