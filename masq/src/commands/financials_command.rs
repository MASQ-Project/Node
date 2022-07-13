// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::commands::financials_command::ChangeDone::{Changed, Unchanged};
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use masq_lib::messages::{
    CustomQueries, CustomQueryResult, FirmQueryResult, RangeQuery, UiFinancialStatistics,
    UiFinancialsRequest, UiFinancialsResponse, UiPayableAccount, UiReceivableAccount,
};
use masq_lib::shared_schema::common_validators::validate_u16;
use masq_lib::short_writeln;
use masq_lib::utils::{plus, ExpectValue};
use num::CheckedMul;
use regex::Regex;
use std::cell::RefCell;
use std::fmt::{Debug, Display};
use std::io::Write;
use std::num::{IntErrorKind, ParseIntError};
use std::ops::Mul;
use std::str::FromStr;
use thousands::Separable;

const FINANCIALS_SUBCOMMAND_ABOUT: &str =
    "Displays financial statistics of this Node. Only valid if Node is already running.";
const TOP_ARG_HELP: &str = "Returns the first N records from both payable and receivable";
const PAYABLE_ARG_HELP: &str = "Enables to configure a detailed query about the payable records by specifying two ranges, one for their age and another for their balance. The required format of the values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const RECEIVABLE_ARG_HELP: &str = "Enables to configure a detailed query about the receivable records by specifying two ranges, one for their age and another for their balance. The required format of the values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const NO_STATS_ARG_HELP: &str = "Disables the statistics that displays by default, with totals of paid and unpaid money from the view of both debtors and creditors. This argument is not allowed alone and must stand before other arguments";
const GWEI_HELP: &str =
    "Orders rendering money in Gwei of MASQ instead of whole MASQ which is the default";
const WALLET_ADDRESS_LENGTH: usize = 42;

#[derive(Debug, PartialEq)]
pub struct FinancialsCommand {
    stats_required: bool,
    top_records_opt: Option<u16>,
    custom_queries_opt: Option<CustomQueryInput>,
    gwei_precision: bool,
}

#[derive(Debug, PartialEq)]
struct CustomQueryInput {
    query: RefCell<Option<CustomQueries>>,
    user_payable_format_opt: Option<UsersLiteralRangeDefinition>,
    user_receivable_format_opt: Option<UsersLiteralRangeDefinition>,
}

type UsersLiteralRangeDefinition = ((String, String), (String, String));

pub fn financials_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("financials")
        .about(FINANCIALS_SUBCOMMAND_ABOUT)
        .arg(
            Arg::with_name("top")
                .help(TOP_ARG_HELP)
                .value_name("TOP")
                .long("top")
                .short("t")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .validator(validate_u16),
        )
        .arg(
            Arg::with_name("payable")
                .help(PAYABLE_ARG_HELP)
                .value_name("PAYABLE")
                .long("payable")
                .short("p")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .validator(validate_two_ranges::<u64>),
        )
        .arg(
            Arg::with_name("receivable")
                .help(RECEIVABLE_ARG_HELP)
                .value_name("PAYABLE")
                .long("receivable")
                .short("r")
                .required(false)
                .case_insensitive(false)
                .takes_value(true)
                .validator(validate_two_ranges::<i64>),
        )
        .arg(
            Arg::with_name("no-stats")
                .help(NO_STATS_ARG_HELP)
                .value_name("NO-STATS")
                .long("no-stats")
                .short("s")
                .case_insensitive(false)
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("gwei")
                .help(GWEI_HELP)
                .value_name("GWEI")
                .long("gwei")
                .short("g")
                .case_insensitive(false)
                .takes_value(false)
                .required(false),
        )
        .groups(&[
            ArgGroup::with_name("no-stats-group")
                .args(&["no-stats"])
                .requires("other-options-group"),
            ArgGroup::with_name("other-options-group")
                .args(&["receivable", "payable", "top"])
                .multiple(true),
        ])
}

impl Command for FinancialsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiFinancialsRequest {
            stats_required: self.stats_required,
            top_records_opt: self.top_records_opt,
            custom_queries_opt: self
                .custom_queries_opt
                .as_ref()
                .map(|queries| queries.query.take().expectv("custom query")),
        };
        let output: Result<UiFinancialsResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        let gwei_flag = self.gwei_precision;
        match output {
            Ok(response) => {
                let stdout = context.stdout();
                if let Some(stats) = response.stats_opt {
                    self.process_financial_status(stdout, stats, gwei_flag)
                };
                if let Some(top_records) = response.top_records_opt {
                    self.process_top_records(stdout, top_records, gwei_flag)
                }
                if let Some(custom_query) = response.custom_query_records_opt {
                    self.process_custom_query(stdout, custom_query, gwei_flag)
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

macro_rules! dump_statistics_lines {
 ($stdout: ident, $gwei_flag:expr,$stats:expr,$($parameter_name: literal),+, $($gwei:ident),+) => {
       $(dump_parameter_line(
                $stdout,
                $parameter_name,
                &Self::process_gwei_into_right_format($stats.$gwei, $gwei_flag),
            )
       );+
    }
}

macro_rules! process_top_records {
    ($self: expr, $stdout: expr, $account_type: literal, $headings: expr, $top_records: expr, $render_accounts_fn:ident, $write_headings_fn:ident) => {
        if !$top_records.is_empty() {
            $self.title_for_tops($stdout, $account_type);
            $self.$render_accounts_fn($stdout, $top_records, &$headings);
        } else {
            $self.title_for_tops($stdout, $account_type);
            Self::no_records_found($stdout, $headings.words(), Self::$write_headings_fn)
        }
    };
}

macro_rules! process_custom_query {
    ($self:expr, $stdout: expr, $account_type: literal, $headings: expr, $correct_field:ident,$custom_query: expr, $render_accounts_fn:ident, $write_headings_fn:ident) => {
        if let Some(accounts) = $custom_query {
            Self::title_for_custom_query(
                $stdout,
                $account_type,
                $self
                    .custom_queries_opt
                    .as_ref()
                    .expectv("custom query")
                    .$correct_field
                    .as_ref()
                    .expectv("custom query field"),
            );
            $self.$render_accounts_fn($stdout, accounts, $headings)
        } else if $self
            .custom_queries_opt
            .as_ref()
            .expectv("custom query input")
            .$correct_field
            .is_some()
        {
            Self::title_for_custom_query(
                $stdout,
                $account_type,
                $self
                    .custom_queries_opt
                    .as_ref()
                    .expectv("custom query")
                    .$correct_field
                    .as_ref()
                    .expectv("custom query field"),
            );
            Self::no_records_found($stdout, $headings.words(), Self::$write_headings_fn)
        }
    };
}

impl FinancialsCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match financials_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(e.to_string()),
        };
        let stats_required = !matches.is_present("no-stats");
        let top_records_opt = Self::parse_top_records_arg(&matches);
        let gwei_precision = matches.is_present("gwei");
        Ok(Self {
            stats_required,
            top_records_opt,
            custom_queries_opt: match (
                Self::parse_range_query_arg::<u64>(&matches, "payable"),
                Self::parse_range_query_arg::<i64>(&matches, "receivable"),
            ) {
                (None, None) => None,
                (payable_opt, receivable_opt) => {
                    let (payable_opt, user_payable_format_opt) = if let Some(x) = payable_opt {
                        x
                    } else {
                        (None, None)
                    };
                    let (receivable_opt, user_receivable_format_opt) =
                        if let Some(x) = receivable_opt {
                            x
                        } else {
                            (None, None)
                        };
                    Some(CustomQueryInput {
                        query: RefCell::new(Some(CustomQueries {
                            payable_opt,
                            receivable_opt,
                        })),
                        user_payable_format_opt,
                        user_receivable_format_opt,
                    })
                }
            },
            gwei_precision,
        })
    }

    fn process_financial_status(
        &self,
        stdout: &mut dyn Write,
        stats: UiFinancialStatistics,
        gwei_flag: bool,
    ) {
        Self::financial_status_totals_title(stdout, gwei_flag);
        dump_statistics_lines!(
            stdout,
            gwei_flag,
            stats,
            "Unpaid and pending payable:",
            "Paid payable:",
            "Unpaid receivable:",
            "Paid receivable:",
            total_unpaid_and_pending_payable_gwei,
            total_paid_payable_gwei,
            total_unpaid_receivable_gwei,
            total_paid_receivable_gwei
        );
    }

    fn process_top_records(
        &self,
        stdout: &mut dyn Write,
        top_records: FirmQueryResult,
        gwei_flag: bool,
    ) {
        let (payable_headings, receivable_headings) = Self::prepare_headings_of_records(gwei_flag);
        process_top_records!(
            self,
            stdout,
            "payable",
            payable_headings,
            top_records.payable,
            render_payable,
            write_payable_headings
        );
        process_top_records!(
            self,
            stdout,
            "receivable",
            receivable_headings,
            top_records.receivable,
            render_receivable,
            write_receivable_headings
        );
    }

    fn process_custom_query(
        &self,
        stdout: &mut dyn Write,
        custom_query_result: CustomQueryResult,
        gwei_flag: bool,
    ) {
        let (payable_headings, receivable_headings) = Self::prepare_headings_of_records(gwei_flag);
        process_custom_query!(
            self,
            stdout,
            "payable",
            &payable_headings,
            user_payable_format_opt,
            custom_query_result.payable_opt,
            render_payable,
            write_payable_headings
        );
        process_custom_query!(
            self,
            stdout,
            "receivable",
            &receivable_headings,
            user_receivable_format_opt,
            custom_query_result.receivable_opt,
            render_receivable,
            write_receivable_headings
        );
    }

    fn parse_top_records_arg(matches: &ArgMatches) -> Option<u16> {
        matches.value_of("top").map(|str| {
            str.parse::<u16>()
                .expect("top records count not properly required")
        })
    }

    fn parse_range_query_arg<
        'a,
        T: FromStr<Err = ParseIntError> + From<u32> + CheckedMul + Display,
    >(
        matches: &'a ArgMatches,
        parameter_name: &'a str,
    ) -> Option<(Option<RangeQuery<T>>, Option<UsersLiteralRangeDefinition>)> {
        matches.value_of(parameter_name).map(|double| {
            //this is already after tight validation
            let separated_ranges = double.split('|').collect::<Vec<&str>>();
            let time_range = separated_ranges[0].split('-').collect::<Vec<&str>>();
            let (min_age, max_age) =
                parse_time_params(&time_range).expect("blows up after validation?");
            let (min_amount_num, max_amount_num, min_amount_str, max_amount_str) =
                parse_masq_range_to_gwei(separated_ranges[1]).expect("blows up after validation?");
            //I'm arranging these types so that I can easily use them in the next step outside of here
            (
                Some(RangeQuery {
                    min_age_seconds: min_age,
                    max_age_seconds: max_age,
                    min_amount_gwei: min_amount_num,
                    max_amount_gwei: max_amount_num,
                }),
                Some((
                    (time_range[0].to_string(), time_range[1].to_string()),
                    (min_amount_str, max_amount_str),
                )),
            )
        })
    }

    fn print_gwei_or_masq_unit_type(gwei: bool) -> &'static str {
        if gwei {
            "Gwei"
        } else {
            "MASQ"
        }
    }

    fn prepare_headings_of_records(gwei: bool) -> (PayableHeadings, ReceivableHeadings) {
        let balance = if !gwei {
            "Balance [MASQ]"
        } else {
            "Balance [Gwei]"
        };
        (
            PayableHeadings(vec!["Wallet", "Age [s]", balance, "Pending tx"], gwei),
            ReceivableHeadings(vec!["Wallet", "Age [s]", balance], gwei),
        )
    }

    fn convert_masq_from_gwei_and_format_well<T>(gwei: T) -> String
    where
        T: Display + PartialEq + From<u32>,
    {
        let stringified = gwei.to_string();
        let gross_length = stringified.len();
        if gwei == T::from(0) {
            return "0".to_string();
        }
        match gross_length {
            x if x <= 7 => "< 0.01".to_string(),
            x => {
                let full_range = &stringified[0..gross_length - 7];
                let is_positive = &full_range[..=0] != "-";
                let (decimals, integer_part_unsigned) = {
                    let (decimal_length, integer_part) = match x {
                        x if x == 8 && is_positive => (1, "0"),
                        x if x == 8 => return "-0.01 < x < 0".to_string(),
                        x if x == 9 && is_positive => (2, "0"),
                        x if x == 9 => (1, "0"),
                        _ => (
                            2,
                            &full_range[if is_positive { 0 } else { 1 }..full_range.len() - 2],
                        ),
                    };
                    (
                        Self::proper_decimal_format(full_range, decimal_length),
                        integer_part,
                    )
                };
                let numerical: u64 = integer_part_unsigned
                    .parse()
                    .expect("preceding checks failed");
                let comma_delimited_int_part = numerical.separate_with_commas();
                format!(
                    "{}{}.{}",
                    if is_positive { "" } else { "-" },
                    comma_delimited_int_part,
                    decimals
                )
            }
        }
    }

    fn proper_decimal_format(whole_number: &str, decimal_length_except_zeros: usize) -> String {
        match decimal_length_except_zeros {
            1 => format!(
                "0{}",
                (&whole_number
                    [whole_number.len() - decimal_length_except_zeros..whole_number.len()])
            ),
            2 => (&whole_number
                [whole_number.len() - decimal_length_except_zeros..whole_number.len()])
                .to_string(),
            x => panic!("Broken code: this number {} shouldn't get here", x),
        }
    }

    fn process_gwei_into_right_format<T: Separable + Display + PartialEq + From<u32>>(
        gwei: T,
        should_be_gwei: bool,
    ) -> String {
        if should_be_gwei {
            gwei.separate_with_commas()
        } else {
            Self::convert_masq_from_gwei_and_format_well(gwei)
        }
    }

    fn financial_status_totals_title(stdout: &mut dyn Write, gwei: bool) {
        let title = format!(
            "Financial status totals in {}",
            Self::print_gwei_or_masq_unit_type(gwei)
        );
        short_writeln!(stdout, "{}", title);
        short_writeln!(stdout, "{}", "=".repeat(title.len()));
    }

    fn title_for_tops(&self, stdout: &mut dyn Write, distinguished: &str) {
        Self::double_blank_line(stdout);
        let requested_count = self.top_records_opt.expectv("requested count");
        short_writeln!(
            stdout,
            "Top {} {} accounts\n{}",
            requested_count,
            distinguished,
            "=".repeat(14 + distinguished.len() + requested_count.to_string().len())
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
        optimal_widths.iter().sum::<usize>() + WALLET_ADDRESS_LENGTH + optimal_widths.len() + 2
    }

    fn heading_underscore(optimal_widths: &[usize]) -> String {
        "-".repeat(Self::full_length(optimal_widths))
    }

    fn prepare_trait_objects<W: WidthInfo>(accounts: &[W]) -> Vec<&dyn (WidthInfo)> {
        accounts
            .iter()
            .map(|each| each as &dyn WidthInfo)
            .collect::<Vec<&dyn WidthInfo>>()
    }

    fn render_payable(
        &self,
        stdout: &mut dyn Write,
        accounts: Vec<UiPayableAccount>,
        headings: &PayableHeadings,
    ) {
        let optimal_widths = Self::width_precise_calculation(
            headings.words(),
            &Self::prepare_trait_objects(&accounts),
        );
        Self::write_payable_headings(stdout, headings.words(), &optimal_widths);
        accounts.iter().for_each(|account| {
            Self::render_single_payable(stdout, account, &optimal_widths, headings.is_gwei())
        });
    }

    fn write_payable_headings(stdout: &mut dyn Write, headings: &[&str], optimal_widths: &[usize]) {
        short_writeln!(
            stdout,
            "|{:^wallet_width$}|{:^age_width$}|{:^balance_width$}|{:^rowid_width$}|\n{}",
            headings[0],
            headings[1],
            headings[2],
            headings[3],
            Self::heading_underscore(optimal_widths),
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
        gwei: bool,
    ) {
        short_writeln!(
            stdout,
            "|{:wallet_width$}|{:>age_width$}|{:>balance_width$}|{:>rowid_width$}|",
            account.wallet,
            account.age.separate_with_commas(),
            Self::process_gwei_into_right_format(account.balance_gwei, gwei),
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

    fn render_receivable(
        &self,
        stdout: &mut dyn Write,
        accounts: Vec<UiReceivableAccount>,
        headings: &ReceivableHeadings,
    ) {
        let optimal_widths = Self::width_precise_calculation(
            headings.words(),
            &Self::prepare_trait_objects(&accounts),
        );
        Self::write_receivable_headings(stdout, headings.words(), &optimal_widths);
        accounts.iter().for_each(|account| {
            Self::render_single_receivable(stdout, account, &optimal_widths, headings.is_gwei())
        });
    }

    fn write_receivable_headings(
        stdout: &mut dyn Write,
        headings: &[&str],
        optimal_widths: &[usize],
    ) {
        short_writeln!(
            stdout,
            "|{:^wallet_width$}|{:^age_width$}|{:^balance_width$}|\n{}",
            headings[0],
            headings[1],
            headings[2],
            Self::heading_underscore(optimal_widths),
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = optimal_widths[0],
            balance_width = optimal_widths[1],
        );
    }

    fn render_single_receivable(
        stdout: &mut dyn Write,
        account: &UiReceivableAccount,
        width_config: &[usize],
        gwei: bool,
    ) {
        short_writeln!(
            stdout,
            "|{:wallet_width$}|{:>age_width$}|{:>balance_width$}|",
            account.wallet,
            account.age.separate_with_commas(),
            Self::process_gwei_into_right_format(account.balance_gwei, gwei),
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = width_config[0],
            balance_width = width_config[1],
        )
    }

    fn title_for_custom_query(
        stdout: &mut dyn Write,
        distinguished: &str,
        user_written_ranges: &UsersLiteralRangeDefinition,
    ) {
        let processed = Self::correct_users_writing_if_needed(user_written_ranges);
        let (time, amounts) = processed.value();
        Self::double_blank_line(stdout);
        short_writeln!(
            stdout,
            "Specific {} query: {} sec {} MASQ\n{}",
            distinguished,
            time,
            amounts,
            "=".repeat(27 + distinguished.len() + time.len() + amounts.len())
        )
    }

    fn correct_users_writing_if_needed(
        user_ranges: &UsersLiteralRangeDefinition,
    ) -> ChangeDone<(String, String)> {
        fn apply_care(str: &String) -> Option<String> {
            fn front_care(str: &String, decimal_dot_position: Option<usize>) -> String {
                fn count_leading_zeros(str: &str) -> (usize, bool) {
                    str.chars().fold((0, true), |acc, char| {
                        if acc.1 {
                            if char == '0' {
                                (acc.0 + 1, true)
                            } else {
                                (acc.0, false)
                            }
                        } else {
                            acc
                        }
                    })
                }
                let leading_zeros = count_leading_zeros(str.as_str());
                str.chars()
                    .skip(if leading_zeros.0 == 0 {
                        0
                    } else {
                        leading_zeros.0
                            - if let Some(idx) = decimal_dot_position {
                                if (idx - leading_zeros.0) == 0 {
                                    1
                                } else {
                                    0
                                }
                            } else if leading_zeros.0 == str.len() {
                                1
                            } else {
                                0
                            }
                    })
                    .collect()
            }
            fn make_decision(after_care: String, before: &String) -> Option<String> {
                if after_care.len() != before.len() {
                    Some(after_care)
                } else {
                    None
                }
            }
            if let Some(idx) = str.chars().position(|char| char == '.') {
                let after_care = front_care(str, Some(idx))
                    .chars()
                    .rev()
                    .skip_while(|char| *char == '0')
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>();
                if after_care.len() != str.len() {
                    Some(after_care)
                } else {
                    None
                }
            } else {
                let after_care = front_care(str, None);
                make_decision(after_care, str)
            }
        }
        let ((time_min, time_max), (amount_min, amount_max)) = user_ranges;
        match (
            apply_care(time_min),
            apply_care(time_max),
            apply_care(amount_min),
            apply_care(amount_max),
        ) {
            (None, None, None, None) => Unchanged((
                format!("{}-{}", time_min, time_max),
                format!("{}-{}", amount_min, amount_max),
            )),
            (a, b, c, d) => Changed((
                format!(
                    "{}-{}",
                    a.unwrap_or_else(|| time_min.to_string()),
                    b.unwrap_or_else(|| time_max.to_string())
                ),
                format!(
                    "{}-{}",
                    c.unwrap_or_else(|| amount_min.to_string()),
                    d.unwrap_or_else(|| amount_max.to_string())
                ),
            )),
        }
    }

    fn no_records_found<F>(stdout: &mut dyn Write, headings: &[&str], write_headings: F)
    where
        F: Fn(&mut dyn Write, &[&str], &[usize]),
    {
        let headings_widths = headings
            .iter()
            .skip(1)
            .map(|word| word.len() + 2)
            .collect::<Vec<usize>>();
        let full_length = Self::full_length(&headings_widths);
        write_headings(stdout, headings, &headings_widths);
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

#[derive(Debug, PartialEq)]
enum ChangeDone<T> {
    Changed(T),
    Unchanged(T),
}

impl<T> ChangeDone<T> {
    fn value(self) -> T {
        match self {
            Changed(val) => val,
            Unchanged(val) => val,
        }
    }
}

trait Headings {
    fn words(&self) -> &[&'static str];
    fn is_gwei(&self) -> bool;
}

struct PayableHeadings(Vec<&'static str>, bool);
impl Headings for PayableHeadings {
    fn words(&self) -> &[&'static str] {
        &self.0
    }

    fn is_gwei(&self) -> bool {
        self.1
    }
}

struct ReceivableHeadings(Vec<&'static str>, bool);
impl Headings for ReceivableHeadings {
    fn words(&self) -> &[&'static str] {
        &self.0
    }

    fn is_gwei(&self) -> bool {
        self.1
    }
}

trait WidthInfo {
    fn widths(&self) -> Vec<usize>;
}

//we can leave out special computation for balances in MASQ with dot and two decimal digits,
//it would require more MASQ than possible
impl WidthInfo for UiPayableAccount {
    fn widths(&self) -> Vec<usize> {
        vec![
            FinancialsCommand::count_length_with_comma_separators(self.age),
            FinancialsCommand::count_length_with_comma_separators(self.balance_gwei),
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
            FinancialsCommand::count_length_with_comma_separators(self.balance_gwei),
        ]
    }
}

pub fn validate_two_ranges<N>(double: String) -> Result<(), String>
where
    N: FromStr<Err = ParseIntError>
        + From<u32>
        + Mul<Output = N>
        + PartialOrd
        + Display
        + CheckedMul,
{
    fn checked_division<'a>(
        str: &'a str,
        delim: char,
        err_msg: &'a str,
    ) -> Result<Vec<&'a str>, String> {
        let ranges = str.split(delim).collect::<Vec<&str>>();
        if ranges.len() != 2 {
            return Err(err_msg.to_string());
        }
        Ok(ranges)
    }
    let separate_ranges = checked_division(&double, '|', "Central vertical delimiter misused")?;
    let time_range = checked_division(separate_ranges[0], '-', "First range is formatted wrong")?;
    let (min_age, max_age) = parse_time_params(&time_range)?;
    let (min_amount, max_amount, _, _): (N, N, _, _) =
        parse_masq_range_to_gwei(separate_ranges[1])?;
    if min_age >= max_age || min_amount >= max_amount {
        Err("Both ranges must be ascending".to_string())
    } else {
        Ok(())
    }
}

fn parse_integer<N: FromStr<Err = ParseIntError>>(str_num: &str) -> Result<N, String> {
    str::parse::<N>(str_num).map_err(|e| match e.kind() {
        IntErrorKind::NegOverflow | IntErrorKind::PosOverflow => panic!(
            "Broken code: Clap validation should have detected the overflow of {} earlier",
            str_num
        ),
        _ => format!(
            "Non numeric value > {} <, all must be valid numbers",
            str_num
        ),
    })
}

fn parse_time_params(time_range: &[&str]) -> Result<(u64, u64), String> {
    Ok((parse_integer(time_range[0])?, parse_integer(time_range[1])?))
}

fn extract_masq_and_return_gwei_str(range_str: &str) -> Result<(String, String), String> {
    let regex = Regex::new("(-?\\d+\\.?\\d*)\\s*-\\s*(-?\\d+\\.?\\d*)").expect("wrong regex");
    match regex.captures(range_str).map(|captures| {
        let fetch = |idx: usize| captures.get(idx).map(|catch| catch.as_str().to_owned());
        (fetch(1), fetch(2))
    }) {
        Some((Some(first), Some(second))) => Ok((first, second)),
        _ => Err("Second range in improper format".to_string()),
    }
}

pub fn parse_masq_range_to_gwei<N>(range_str: &str) -> Result<(N, N, String, String), String>
where
    N: FromStr<Err = ParseIntError> + From<u32> + Mul<Output = N> + CheckedMul + Display,
{
    let (first, second) = extract_masq_and_return_gwei_str(range_str)?;
    Ok((
        process_optionally_fragmentary_number(&first)?,
        process_optionally_fragmentary_number(&second)?,
        first,
        second,
    ))
}

fn process_optionally_fragmentary_number<N>(num: &str) -> Result<N, String>
where
    N: FromStr<Err = ParseIntError> + From<u32> + CheckedMul + Display,
{
    let final_unit_conversion = |parse_result: N, pow_factor: u32| {
        if let Some(int) = parse_result.checked_mul(&N::from(10_u32.pow(pow_factor))) {
            Ok(int)
        } else {
            Err(format!("Attempt with too big amount of MASQ: {}", num))
        }
    };
    if let Some(dot_idx) = num.chars().position(|char| char == '.') {
        pre_parsing_check(num, dot_idx)?;
        let decimal_num_count = num.chars().count() - dot_idx - 1;
        let root_parsed: N =
            parse_integer(&num.chars().filter(|char| *char != '.').collect::<String>())?;
        final_unit_conversion(root_parsed, 9 - decimal_num_count as u32)
    } else {
        let root_parsed = parse_integer::<N>(num)?;
        final_unit_conversion(root_parsed, 9)
    }
}

fn pre_parsing_check(num: &str, dot_idx: usize) -> Result<(), String> {
    if dot_idx == num.len() - 1 {
        Err("Ending dot at decimal number is unsupported".to_string())
    } else if num.chars().filter(|char| *char == '.').count() != 1 {
        Err("Misused decimal number dot delimiter".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryError, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{
        CustomQueryResult, FirmQueryResult, ToMessageBody, UiFinancialStatistics,
        UiFinancialsResponse, UiPayableAccount, UiReceivableAccount,
    };
    use masq_lib::utils::array_of_borrows_to_vec;
    use std::panic::catch_unwind;
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
        assert_eq!(PAYABLE_ARG_HELP,"Enables to configure a detailed query about the payable records by specifying two ranges, one for their age and another for their balance. The required format of the values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>");
        assert_eq!(RECEIVABLE_ARG_HELP,"Enables to configure a detailed query about the receivable records by specifying two ranges, one for their age and another for their balance. The required format of the values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>");
        assert_eq!(NO_STATS_ARG_HELP,"Disables the statistics that displays by default, with totals of paid and unpaid money from the view of both debtors and creditors. This argument is not allowed alone and must stand before other arguments");
        assert_eq!(
            GWEI_HELP,
            "Orders rendering money in Gwei of MASQ instead of whole MASQ which is the default"
        );
        assert_eq!(WALLET_ADDRESS_LENGTH, 42);
    }

    #[test]
    fn command_factory_default_command() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 0,
                total_paid_payable_gwei: 1111,
                total_unpaid_receivable_gwei: 2222,
                total_paid_receivable_gwei: 3333,
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
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 0,
                total_paid_payable_gwei: 1111,
                total_unpaid_receivable_gwei: 2222,
                total_paid_receivable_gwei: 3333,
            }),
            top_records_opt: Some(FirmQueryResult {
                payable: vec![],
                receivable: vec![],
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
                "200-450|480000-158000008",
                "--gwei",
            ]))
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn command_factory_big_masq_values_supplied_are_not_fatal_for_non_decimal_values() {
        let factory = CommandFactoryReal::new();
        let result = factory
            .make(&array_of_borrows_to_vec(&[
                "financials",
                "--top",
                "10",
                "--payable",
                "200-450|480000-15800000800045",
            ]))
            .unwrap_err();
        let err_message = match result {
            CommandFactoryError::CommandSyntax(msg) => msg,
            x => panic!("we expected CommandSyntax error but got: {:?}", x),
        };

        assert!(err_message.contains("Attempt with too big amount of MASQ: 15800000800045"))
    }

    #[test]
    fn command_factory_big_masq_values_supplied_are_not_fatal_for_decimal_values() {
        let factory = CommandFactoryReal::new();
        let result = factory
            .make(&array_of_borrows_to_vec(&[
                "financials",
                "--top",
                "10",
                "--payable",
                "200-450|480045454455.00-158000008000455",
            ]))
            .unwrap_err();
        let err_message = match result {
            CommandFactoryError::CommandSyntax(msg) => msg,
            x => panic!("we expected CommandSyntax error but got: {:?}", x),
        };

        assert!(err_message.contains("Attempt with too big amount of MASQ: 480045454455.00"))
    }

    #[test]
    fn command_factory_no_stats_forbidden_if_no_other_arg_present() {
        let factory = CommandFactoryReal::new();

        let result = factory.make(&array_of_borrows_to_vec(&["financials", "--no-stats"]));

        let err = match result {
            Ok(_) => panic!("we expected error but got ok"),
            Err(CommandFactoryError::CommandSyntax(err_msg)) => err_msg,
            Err(e) => panic!("we expected CommandSyntax error but got: {:?}", e),
        };
        assert!(err.contains("The following required arguments were not provided:"));
        assert!(err.contains(
            "financials <--no-stats> <--receivable <PAYABLE>|--payable <PAYABLE>|--top <TOP>>"
        ));
    }

    #[test]
    fn financials_command_allows_shorthand_arguments() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let irrelevant_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: None,
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "-g",
            "-t",
            "123",
            "-p",
            "0-350000|0.005-9.000000000",
            "-r",
            "5000-10000|0.000004000-50.003000000",
            "-s",
        ]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(irrelevant_response.tmb(1)));
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: Some(123),
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_seconds: 0,
                            max_age_seconds: 350000,
                            min_amount_gwei: 5000000,
                            max_amount_gwei: 9000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_seconds: 5000,
                            max_age_seconds: 10000,
                            min_amount_gwei: 4000,
                            max_amount_gwei: 50003000000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[test]
    fn financials_command_allows_obscure_leading_zeros_in_positive_numbers() {
        let args =
            array_of_borrows_to_vec(&["financials", "--receivable", "05000-0010000|040-050"]);

        let result = FinancialsCommand::new(&args).unwrap();

        assert_eq!(
            result,
            FinancialsCommand {
                stats_required: true,
                top_records_opt: None,
                custom_queries_opt: Some(CustomQueryInput {
                    query: RefCell::new(Some(CustomQueries {
                        payable_opt: None,
                        receivable_opt: Some(RangeQuery {
                            min_age_seconds: 5000,
                            max_age_seconds: 10000,
                            min_amount_gwei: 40000000000,
                            max_amount_gwei: 50000000000
                        })
                    })),
                    user_payable_format_opt: None,
                    user_receivable_format_opt: Some(transpose_inputs_to_nested_tuples([
                        "05000", "0010000", "040", "050"
                    ]))
                }),
                gwei_precision: false
            }
        );
    }

    #[test]
    fn financials_command_allows_obscure_leading_zeros_in_negative_numbers() {
        let args = array_of_borrows_to_vec(&["financials", "--receivable", "5000-10000|-050--040"]);

        let result = FinancialsCommand::new(&args).unwrap();

        assert_eq!(
            result,
            FinancialsCommand {
                stats_required: true,
                top_records_opt: None,
                custom_queries_opt: Some(CustomQueryInput {
                    query: RefCell::new(Some(CustomQueries {
                        payable_opt: None,
                        receivable_opt: Some(RangeQuery {
                            min_age_seconds: 5000,
                            max_age_seconds: 10000,
                            min_amount_gwei: -50000000000,
                            max_amount_gwei: -40000000000
                        })
                    })),
                    user_payable_format_opt: None,
                    user_receivable_format_opt: Some(transpose_inputs_to_nested_tuples([
                        "5000", "10000", "-050", "-040"
                    ]))
                }),
                gwei_precision: false
            }
        );
    }

    #[test]
    fn default_financials_command_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 1_166_880_215,
                total_paid_payable_gwei: 78_455_555,
                total_unpaid_receivable_gwei: -55_000_400,
                total_paid_receivable_gwei: 1_278_766_555_456,
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
                Financial status totals in MASQ\n\
                ===============================\n\
                Unpaid and pending payable:       1.16\n\
                Paid payable:                     0.07\n\
                Unpaid receivable:                -0.05\n\
                Paid receivable:                  1,278.76\n"
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
    fn proper_decimal_format_expect_only_one_and_two() {
        fn test_body(num: usize) -> String {
            let panic = catch_unwind(|| FinancialsCommand::proper_decimal_format("456565", num))
                .unwrap_err();
            let panic_msg = panic.downcast_ref::<String>().unwrap();
            panic_msg.to_owned()
        }

        let first_panic_msg = test_body(0);
        let second_panic_msg = test_body(3);

        assert_eq!(
            first_panic_msg,
            "Broken code: this number 0 shouldn't get here"
        );
        assert_eq!(
            second_panic_msg,
            "Broken code: this number 3 shouldn't get here"
        );
    }

    fn transpose_inputs_to_nested_tuples(
        inputs: [&str; 4],
    ) -> ((String, String), (String, String)) {
        (
            (inputs[0].to_string(), inputs[1].to_string()),
            (inputs[2].to_string(), inputs[3].to_string()),
        )
    }

    #[test]
    fn correct_users_writing_if_needed_handles_leading_and_tailing_zeros() {
        let result =
            FinancialsCommand::correct_users_writing_if_needed(&transpose_inputs_to_nested_tuples(
                ["00045656", "0354865.1500000", "000124856", "01561785.3300"],
            ));

        assert_eq!(
            result,
            Changed((
                "45656-354865.15".to_string(),
                "124856-1561785.33".to_string()
            ))
        )
    }

    #[test]
    fn correct_users_writing_if_needed_returns_none_if_no_change() {
        let result = FinancialsCommand::correct_users_writing_if_needed(
            &transpose_inputs_to_nested_tuples(["456500", "35481533", "-500", "0.4545"]),
        );

        assert_eq!(
            result,
            Unchanged(("456500-35481533".to_string(), "-500-0.4545".to_string()))
        )
    }

    #[test]
    fn correct_users_writing_if_needed_returns_none_if_no_change_with_negative_range() {
        let result = FinancialsCommand::correct_users_writing_if_needed(
            &transpose_inputs_to_nested_tuples(["456500", "35481533", "-500", "-45"]),
        );

        assert_eq!(
            result,
            Unchanged(("456500-35481533".to_string(), "-500--45".to_string()))
        )
    }

    #[test]
    fn correct_users_writing_if_needed_leaves_non_decimal_numbers_untouched_from_right() {
        let result = FinancialsCommand::correct_users_writing_if_needed(
            &transpose_inputs_to_nested_tuples(["456500000", "000354815", "0033330", "000454"]),
        );

        assert_eq!(
            result,
            Changed(("456500000-354815".to_string(), "33330-454".to_string()))
        )
    }

    #[test]
    fn correct_users_writing_if_needed_threats_0_followed_decimal_numbers_gently() {
        let result =
            FinancialsCommand::correct_users_writing_if_needed(&transpose_inputs_to_nested_tuples(
                ["0.45545000", "000.333300", "000.00010000", "565.454500"],
            ));

        assert_eq!(
            result,
            Changed(("0.45545-0.3333".to_string(), "0.0001-565.4545".to_string()))
        )
    }

    #[test]
    #[should_panic(
        expected = "Broken code: Clap validation should have detected the overflow of 40000000000000000000 earlier"
    )]
    fn parse_integer_overflow_indicates_broken_code() {
        let _: Result<u64, String> = parse_integer("40000000000000000000");
    }

    fn response_of_everything_demanded_or_without_stats(with_stats: bool) -> UiFinancialsResponse {
        UiFinancialsResponse {
            stats_opt: if with_stats {
                Some(UiFinancialStatistics {
                    total_unpaid_and_pending_payable_gwei: 116688555,
                    total_paid_payable_gwei: 235555554578,
                    total_unpaid_receivable_gwei: 0,
                    total_paid_receivable_gwei: 665557,
                })
            } else {
                None
            },
            top_records_opt: Some(FirmQueryResult {
                payable: vec![
                    UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 150000,
                        balance_gwei: 8,
                        pending_payable_hash_opt: Some(
                            "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                                .to_string(),
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 5645405400,
                        balance_gwei: 68843325667,
                        pending_payable_hash_opt: None,
                    },
                ],
                receivable: vec![
                    UiReceivableAccount {
                        wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                        age: 22000,
                        balance_gwei: 2444533124512,
                    },
                    UiReceivableAccount {
                        wallet: "0x8bA50675e590b545D2128905b89039256Eaa24F6".to_string(),
                        age: 19000,
                        balance_gwei: -328123256546,
                    },
                ],
            }),
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: Some(vec![UiPayableAccount {
                    wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                    age: 150000,
                    balance_gwei: 8,
                    pending_payable_hash_opt: Some(
                        "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                            .to_string(),
                    ),
                }]),
                receivable_opt: None,
            }),
        }
    }

    #[test]
    fn financials_command_everything_demanded_default_units_as_masq() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_of_everything_demanded_or_without_stats(true);
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--top",
            "123",
            "--payable",
            "0-350000|0.005-9",
            "--receivable",
            "5000-10000|0.003000000-5.600070000",
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
                            min_age_seconds: 0,
                            max_age_seconds: 350000,
                            min_amount_gwei: 5000000,
                            max_amount_gwei: 9000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_seconds: 5000,
                            max_age_seconds: 10000,
                            min_amount_gwei: 3000000,
                            max_amount_gwei: 5600070000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), {
            let main_text_block: &str = "\
                Financial status totals in MASQ\n\
                ===============================\n\
                Unpaid and pending payable:       0.11\n\
                Paid payable:                     235.55\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  < 0.01\n\
                \n\
                \n\
                Top 123 payable accounts\n\
                ========================\n\
                |                  Wallet                  |   Age [s]   | Balance [MASQ] |                            Pending tx                            |\n\
                ----------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|      150,000|          < 0.01|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|           68.84|                                                              None|\n\
                \n\
                \n\
                Top 123 receivable accounts\n\
                ===========================\n\
                |                  Wallet                  | Age [s] | Balance [MASQ]  |\n\
                ------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|   22,000|         2,444.53|\n\
                |0x8bA50675e590b545D2128905b89039256Eaa24F6|   19,000|          -328.12|\n\
                \n\
                \n\
                Specific payable query: 0-350000 sec 0.005-9 MASQ\n\
                =================================================\n\
                |                  Wallet                  | Age [s] | Balance [MASQ] |                            Pending tx                            |\n\
                ------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|  150,000|          < 0.01|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                \n\
                \n\
                Specific receivable query: 5000-10000 sec 0.003-5.60007 MASQ\n\
                ============================================================\n\
                |                  Wallet                  | Age [s] | Balance [MASQ] |\n\
                -----------------------------------------------------------------------\n";
            format!(
                "{}                           No records found                            \n",
                main_text_block
            )
        });
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_everything_demanded_with_gwei_precision() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_of_everything_demanded_or_without_stats(true);
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--top",
            "123",
            "--payable",
            "0-350000|0.005-9",
            "--receivable",
            "5000-10000|0.000004-0.4550",
            "--gwei",
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
                            min_age_seconds: 0,
                            max_age_seconds: 350000,
                            min_amount_gwei: 5000000,
                            max_amount_gwei: 9000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_seconds: 5000,
                            max_age_seconds: 10000,
                            min_amount_gwei: 4000,
                            max_amount_gwei: 455000000
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), {
            let main_text_block: &str = "\
                Financial status totals in Gwei\n\
                ===============================\n\
                Unpaid and pending payable:       116,688,555\n\
                Paid payable:                     235,555,554,578\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  665,557\n\
                \n\
                \n\
                Top 123 payable accounts\n\
                ========================\n\
                |                  Wallet                  |   Age [s]   | Balance [Gwei] |                            Pending tx                            |\n\
                ----------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|      150,000|               8|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|  68,843,325,667|                                                              None|\n\
                \n\
                \n\
                Top 123 receivable accounts\n\
                ===========================\n\
                |                  Wallet                  | Age [s] | Balance [Gwei]  |\n\
                ------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|   22,000|2,444,533,124,512|\n\
                |0x8bA50675e590b545D2128905b89039256Eaa24F6|   19,000| -328,123,256,546|\n\
                \n\
                \n\
                Specific payable query: 0-350000 sec 0.005-9 MASQ\n\
                =================================================\n\
                |                  Wallet                  | Age [s] | Balance [Gwei] |                            Pending tx                            |\n\
                ------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|  150,000|               8|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                \n\
                \n\
                Specific receivable query: 5000-10000 sec 0.000004-0.455 MASQ\n\
                =============================================================\n\
                |                  Wallet                  | Age [s] | Balance [Gwei] |\n\
                -----------------------------------------------------------------------\n";
            format!(
                "{}                           No records found                            \n",
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
                total_unpaid_and_pending_payable_gwei: 116688,
                total_paid_payable_gwei: 55555,
                total_unpaid_receivable_gwei: 221144,
                total_paid_receivable_gwei: 66555,
            }),
            top_records_opt: Some(FirmQueryResult {
                payable: vec![],
                receivable: vec![],
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
            "0-400000|355-6000",
            "--receivable",
            "40000-80000|111-10000",
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
                            min_age_seconds: 0,
                            max_age_seconds: 400000,
                            min_amount_gwei: 355000000000,
                            max_amount_gwei: 6000000000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_seconds: 40000,
                            max_age_seconds: 80000,
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
            stdout_arc.lock().unwrap().get_string(),
            "\
|Financial status totals in MASQ
|===============================
|Unpaid and pending payable:       < 0.01
|Paid payable:                     < 0.01
|Unpaid receivable:                < 0.01
|Paid receivable:                  < 0.01
|
|
|Top 10 payable accounts
|=======================
||                  Wallet                  | Age [s] | Balance [MASQ] | Pending tx |
|------------------------------------------------------------------------------------
|                                  No records found                                  \n\
|
|
|Top 10 receivable accounts
|==========================
||                  Wallet                  | Age [s] | Balance [MASQ] |
|-----------------------------------------------------------------------
|                           No records found                            \n\
|
|
|Specific payable query: 0-400000 sec 355-6000 MASQ
|==================================================
||                  Wallet                  | Age [s] | Balance [MASQ] | Pending tx |
|------------------------------------------------------------------------------------
|                                  No records found                                  \n\
|
|
|Specific receivable query: 40000-80000 sec 111-10000 MASQ
|=========================================================
||                  Wallet                  | Age [s] | Balance [MASQ] |
|-----------------------------------------------------------------------
|                           No records found                            "
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
                payable: vec![UiPayableAccount {
                    wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                    age: 5645405400,
                    balance_gwei: 644000000,
                    pending_payable_hash_opt: Some(
                        "0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638"
                            .to_string(),
                    ),
                }],
                receivable: vec![UiReceivableAccount {
                    wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                    age: 11111111,
                    balance_gwei: -4551012,
                }],
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
                Top 7 payable accounts\n\
                ======================\n\
                |                  Wallet                  |   Age [s]   | Balance [MASQ] |                            Pending tx                            |\n\
                ----------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|            0.64|0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638|\n\
                \n\
                \n\
                Top 7 receivable accounts\n\
                =========================\n\
                |                  Wallet                  | Age [s]  | Balance [MASQ] |\n\
                ------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|11,111,111|   -0.01 < x < 0|\n"
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
                        balance_gwei: 9898999888,
                        pending_payable_hash_opt: Some(
                            "0x5fe272ed1e941cc05fbd624ec4b1546cd03c25d53e24ba2c18b11feb83cd4581"
                                .to_string(),
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 70000,
                        balance_gwei: 708090,
                        pending_payable_hash_opt: None,
                    },
                    UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 6089909,
                        balance_gwei: 66658,
                        pending_payable_hash_opt: None,
                    },
                ]),
                receivable_opt: None,
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--payable",
            "3000-40000|88-1000",
            "--no-stats",
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
                            min_age_seconds: 3000,
                            max_age_seconds: 40000,
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
            stdout_arc.lock().unwrap().get_string(),
               "\n\
                \n\
                Specific payable query: 3000-40000 sec 88-1000 MASQ\n\
                ===================================================\n\
                |                  Wallet                  | Age [s] | Balance [MASQ] |                            Pending tx                            |\n\
                ------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|    4,445|            9.89|0x5fe272ed1e941cc05fbd624ec4b1546cd03c25d53e24ba2c18b11feb83cd4581|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|   70,000|          < 0.01|                                                              None|\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|6,089,909|          < 0.01|                                                              None|\n"
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
                        balance_gwei: 9898999888,
                    },
                    UiReceivableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 70000,
                        balance_gwei: 708090,
                    },
                    UiReceivableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 6089909,
                        balance_gwei: 66658,
                    },
                ]),
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--no-stats",
            "--receivable",
            "3000-40000|66-980",
            "--gwei",
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
                            min_age_seconds: 3000,
                            max_age_seconds: 40000,
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
            stdout_arc.lock().unwrap().get_string(),
            "\n\
                \n\
                Specific receivable query: 3000-40000 sec 66-980 MASQ\n\
                =====================================================\n\
                |                  Wallet                  | Age [s] | Balance [Gwei] |\n\
                -----------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|    4,445|   9,898,999,888|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|   70,000|         708,090|\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|6,089,909|          66,658|\n"
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

    #[test]
    fn validate_two_ranges_happy_path() {
        let result = validate_two_ranges::<u64>("454-5000|0.000130-55.0".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_even_integers_are_acceptable_for_masqs_range() {
        let result = validate_two_ranges::<i64>("454-2000|2000-30000".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_even_one_side_negative_range_is_acceptable_for_masqs_range() {
        let result = validate_two_ranges::<i64>("454-2000|-2000-30000".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_even_both_side_negative_range_is_acceptable_for_masqs_range() {
        let result = validate_two_ranges::<i64>("454-2000|-2000--1000".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_misused_central_delimiter() {
        let result = validate_two_ranges::<i64>("45-500545-006".to_string());

        assert_eq!(
            result,
            Err("Central vertical delimiter misused".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_misused_range_delimiter() {
        let result = validate_two_ranges::<i64>("45+500|545+006".to_string());

        assert_eq!(result, Err("First range is formatted wrong".to_string()))
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_time() {
        let result = validate_two_ranges::<u64>("4545-2000|20000.0-30000.0".to_string());

        assert_eq!(result, Err("Both ranges must be ascending".to_string()))
    }

    #[test]
    fn validate_two_ranges_values_the_same_for_time() {
        let result = validate_two_ranges::<i64>("2000-2000|20000.0-30000.0".to_string());

        assert_eq!(result, Err("Both ranges must be ascending".to_string()))
    }

    #[test]
    fn validate_two_ranges_values_the_same_for_masqs() {
        let result = validate_two_ranges::<i64>("1000-2000|20000.0-20000.0".to_string());

        assert_eq!(result, Err("Both ranges must be ascending".to_string()))
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_masqs_but_not_in_decimals() {
        let result = validate_two_ranges::<i64>("2000-4545|30.0-27.0".to_string());

        assert_eq!(result, Err("Both ranges must be ascending".to_string()))
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_masqs_in_decimals() {
        let result = validate_two_ranges::<u64>("2000-4545|20.13-20.11".to_string());

        assert_eq!(result, Err("Both ranges must be ascending".to_string()))
    }

    #[test]
    fn validate_two_ranges_non_numeric_value_error_for_first_range() {
        let result = validate_two_ranges::<i64>("blah-1234|899-999".to_string());

        assert_eq!(
            result,
            Err("Non numeric value > blah <, all must be valid numbers".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_non_numeric_value_error_for_second() {
        let result = validate_two_ranges::<i64>("1000-1234|7878.0-a lot".to_string());

        assert_eq!(result, Err("Second range in improper format".to_string()))
    }

    #[test]
    fn process_optionally_fragmentary_number_dislikes_dot_as_the_last_char() {
        let result = process_optionally_fragmentary_number::<i64>("4556.");

        assert_eq!(
            result,
            Err("Ending dot at decimal number is unsupported".to_string())
        )
    }

    #[test]
    fn process_optionally_fragmentary_number_dislikes_more_than_one_dot() {
        let result = process_optionally_fragmentary_number::<i64>("45.056.000");

        assert_eq!(
            result,
            Err("Misused decimal number dot delimiter".to_string())
        )
    }
}
