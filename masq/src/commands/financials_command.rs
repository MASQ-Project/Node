// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use masq_lib::messages::{
    CustomQueries, CustomQueryResult, FirmQueryResult, RangeQuery, UiFinancialStatistics,
    UiFinancialsRequest, UiFinancialsResponse, UiPayableAccount, UiReceivableAccount,
};
use masq_lib::shared_schema::common_validators::{validate_two_ranges, validate_u16};
use masq_lib::short_writeln;
use masq_lib::utils::{plus, ExpectValue};
use std::fmt::Display;
use std::io::Write;
use std::str::FromStr;
use thousands::Separable;

const FINANCIALS_SUBCOMMAND_ABOUT: &str =
    "Displays financial statistics of this Node. Only valid if Node is already running.";
const TOP_ARG_HELP: &str = "Returns the first N records from both payable and receivable";
const PAYABLE_ARG_HELP: &str = "Enables to configure a detailed query about the payable records by specifying two ranges, one for their age and another for their balance. The required format of the values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const RECEIVABLE_ARG_HELP: &str = "Enables to configure a detailed query about the receivable records by specifying two ranges, one for their age and another for their balance. The required format of the values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const NO_STATS_ARG_HELP: &str = "Disables the statistics that displays by default, with totals of paid and unpaid money from the view of both debtors and creditors. This argument is not allowed alone";
const GWEI_HELP: &str =
    "Orders rendering money in Gwei of MASQ instead of whole MASQ which is the default";
const WALLET_ADDRESS_LENGTH: usize = 42;

#[derive(Debug, Clone)]
pub struct FinancialsCommand {
    stats_required: bool,
    top_records_opt: Option<u16>,
    custom_queries_opt: Option<CustomQueries>,
    gwei_precision: bool,
}

//TODO short-hands???
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
                .validator(validate_u16),
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
                .case_insensitive(false)
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("gwei")
                .help(GWEI_HELP)
                .value_name("GWEI")
                .long("gwei")
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
            custom_queries_opt: self.custom_queries_opt.clone(),
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
    ($self: expr,$stdout: expr, $account_type: literal, $headings: expr, $top_records: expr, $render_accounts_fn:ident,$write_headings_fn:ident) => {
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
    ($self:expr,$stdout: expr, $account_type: literal, $headings: expr, $correct_field:ident,$custom_query: expr,$gwei_flag: expr,$render_accounts_fn:ident,$write_headings_fn:ident) => {
        if let Some(accounts) = $custom_query.$correct_field {
            Self::title_for_custom_query(
                $stdout,
                $account_type,
                $self
                    .custom_queries_opt
                    .as_ref()
                    .expectv("custom query")
                    .$correct_field
                    .as_ref()
                    .expectv("payable custom query"),
                $gwei_flag,
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
                    .expectv("custom query filed"),
                $gwei_flag,
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
        let top_records_opt = matches.value_of("top").map(|str| {
            str.parse::<u16>()
                .expect("top records count not properly required")
        });
        let custom_payable_opt = Self::parse_range_query(&matches, "payable");
        let custom_receivable_opt = Self::parse_range_query(&matches, "receivable");
        let gwei_precision = matches.is_present("gwei");
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
            "Payable",
            &payable_headings,
            payable_opt,
            custom_query_result,
            gwei_flag,
            render_payable,
            write_payable_headings
        );
        process_custom_query!(
            self,
            stdout,
            "Receivable",
            &receivable_headings,
            receivable_opt,
            custom_query_result,
            gwei_flag,
            render_receivable,
            write_receivable_headings
        );
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
                .split('|')
                .map(|half| half.rsplit_once('-').expect("blah"))
                .fold(vec![], |acc, current| plus(plus(acc, current.0), current.1));
            RangeQuery {
                min_age_seconds: Self::parse(params[0], "min_age"),
                max_age_seconds: Self::parse(params[1], "max_age"),
                min_amount_gwei: Self::parse::<T>(params[2], "min_amount"),
                max_amount_gwei: Self::parse::<T>(params[3], "max_amount"),
            }
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
        let stringify = gwei.to_string();
        let gross_length = stringify.len();
        if gwei == T::from(0) {
            return "0".to_string();
        }
        match gross_length {
            x if x <= 7 => "< 0.01".to_string(),
            x => {
                let full_range = &stringify[0..gross_length - 7];
                eprintln!("gwei: {}", gwei);
                eprintln!("fr: {}", full_range);
                let is_positive = if &full_range[..=0] != "-" {
                    true
                } else {
                    false
                };
                let decimal_double = if x > 8 { true } else { false };
                eprintln!("decimal double: {}", decimal_double);
                let (decimals, integer_part_unsigned): (String, &str) = {
                    let (decimal_length, integer_part): (usize, &str) = match x {
                        x if x == 8 && is_positive => (1, "0"),
                        x if x == 8 => todo!(),
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
                let integer_part_checked = if integer_part_unsigned.is_empty() {
                    "0"
                } else {
                    integer_part_unsigned
                };
                let numerical: u64 = integer_part_checked
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

    fn proper_decimal_format(whole_number: &str, decimal_no_zero_length: usize) -> String {
        match decimal_no_zero_length {
            0 => todo!(),
            1 => format!(
                "0{}",
                (&whole_number[whole_number.len() - decimal_no_zero_length..whole_number.len()])
            ),
            2 => (&whole_number[whole_number.len() - decimal_no_zero_length..whole_number.len()])
                .to_string(),
            _ => todo!(),
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

    fn title_for_custom_query<N: Display>(
        stdout: &mut dyn Write,
        distinguished: &str,
        range_query: &RangeQuery<N>,
        gwei: bool,
    ) {
        let unit = Self::print_gwei_or_masq_unit_type(gwei);
        Self::double_blank_line(stdout);
        short_writeln!(
            stdout,
            "{} query with parameters: {}-{} s and {}-{} {}\n{}",
            distinguished,
            range_query.min_age_seconds,
            range_query.max_age_seconds,
            range_query.min_amount_gwei,
            range_query.max_amount_gwei,
            unit,
            "=".repeat(
                34 + distinguished.len()
                    + unit.len()
                    + range_query.min_age_seconds.to_string().len()
                    + range_query.max_age_seconds.to_string().len()
                    + range_query.min_amount_gwei.to_string().len()
                    + range_query.max_amount_gwei.to_string().len()
            )
        )
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

//TODO this could be a problem after I added decimal numbers
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
        assert_eq!(NO_STATS_ARG_HELP,"Disables the statistics that displays by default, with totals of paid and unpaid money from the view of both debtors and creditors. This argument is not allowed alone");
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
                "200-450|48000000111-158000008000",
                "--gwei",
            ]))
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
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

    fn tests_with_everything_demanded_expected_response() -> UiFinancialsResponse {
        UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 116688555,
                total_paid_payable_gwei: 235555554578,
                total_unpaid_receivable_gwei: 0,
                total_paid_receivable_gwei: 665557,
            }),
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
        let expected_response = tests_with_everything_demanded_expected_response();
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
                Top 123 accounts in payable\n\
                ===========================\n\
                |                  Wallet                  |   Age [s]   | Balance [MASQ] |                            Pending tx                            |\n\
                ----------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|      150,000|          < 0.01|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|           68.84|                                                              None|\n\
                \n\
                \n\
                Top 123 accounts in receivable\n\
                ==============================\n\
                |                  Wallet                  | Age [s] | Balance [MASQ]  |\n\
                ------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|   22,000|         2,444.53|\n\
                |0x8bA50675e590b545D2128905b89039256Eaa24F6|   19,000|          -328.12|\n\
                \n\
                \n\
                Payable query with parameters: 0-350000 s and 5000000-9000000000 MASQ\n\
                =====================================================================\n\
                |                  Wallet                  | Age [s] | Balance [MASQ] |                            Pending tx                            |\n\
                ------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|  150,000|          < 0.01|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                \n\
                \n\
                Receivable query with parameters: 5000-10000 s and 3000000-5600070000 MASQ\n\
                ==========================================================================\n\
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
        let expected_response = tests_with_everything_demanded_expected_response();
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--top",
            "123",
            "--payable",
            "0-350000|5000000-9000000000",
            "--receivable",
            "5000-10000|4000-50003000000",
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
                            max_amount_gwei: 50003000000
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
                Top 123 accounts in payable\n\
                ===========================\n\
                |                  Wallet                  |   Age [s]   | Balance [Gwei] |                            Pending tx                            |\n\
                ----------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|      150,000|               8|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|  68,843,325,667|                                                              None|\n\
                \n\
                \n\
                Top 123 accounts in receivable\n\
                ==============================\n\
                |                  Wallet                  | Age [s] | Balance [Gwei]  |\n\
                ------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|   22,000|2,444,533,124,512|\n\
                |0x8bA50675e590b545D2128905b89039256Eaa24F6|   19,000| -328,123,256,546|\n\
                \n\
                \n\
                Payable query with parameters: 0-350000 s and 5000000-9000000000 Gwei\n\
                =====================================================================\n\
                |                  Wallet                  | Age [s] | Balance [Gwei] |                            Pending tx                            |\n\
                ------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440|  150,000|               8|0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e|\n\
                \n\
                \n\
                Receivable query with parameters: 5000-10000 s and 4000-50003000000 Gwei\n\
                ========================================================================\n\
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
                            min_age_seconds: 0,
                            max_age_seconds: 400000,
                            min_amount_gwei: 5000000,
                            max_amount_gwei: 60000000
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_seconds: 40000,
                            max_age_seconds: 80000,
                            min_amount_gwei: 10000,
                            max_amount_gwei: 1000000000
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
|Top 10 accounts in payable
|==========================
||                  Wallet                  | Age [s] | Balance [MASQ] | Pending tx |
|------------------------------------------------------------------------------------
|                                  No records found                                  \n\
|
|
|Top 10 accounts in receivable
|=============================
||                  Wallet                  | Age [s] | Balance [MASQ] |
|-----------------------------------------------------------------------
|                           No records found                            \n\
|
|
|Payable query with parameters: 0-400000 s and 5000000-60000000 MASQ
|===================================================================
||                  Wallet                  | Age [s] | Balance [MASQ] | Pending tx |
|------------------------------------------------------------------------------------
|                                  No records found                                  \n\
|
|
|Receivable query with parameters: 40000-80000 s and 10000-1000000000 MASQ
|=========================================================================
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
                    balance_gwei: 1352444551012,
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
                Top 7 accounts in payable\n\
                =========================\n\
                |                  Wallet                  |   Age [s]   | Balance [MASQ] |                            Pending tx                            |\n\
                ----------------------------------------------------------------------------------------------------------------------------------------------\n\
                |0xA884A2F1A5Ec6C2e499644666a5E6af97B966888|5,645,405,400|            0.64|0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638|\n\
                \n\
                \n\
                Top 7 accounts in receivable\n\
                ============================\n\
                |                  Wallet                  | Age [s]  | Balance [MASQ]  |\n\
                -------------------------------------------------------------------------\n\
                |0x6e250504DdfFDb986C4F0bb8Df162503B4118b05|11,111,111|         1,352.44|\n"
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
                            min_age_seconds: 3000,
                            max_age_seconds: 40000,
                            min_amount_gwei: 8866,
                            max_amount_gwei: 10000000
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
                Payable query with parameters: 3000-40000 s and 8866-10000000 MASQ\n\
                ==================================================================\n\
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
                            min_age_seconds: 3000,
                            max_age_seconds: 40000,
                            min_amount_gwei: 8866,
                            max_amount_gwei: 10000000
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
