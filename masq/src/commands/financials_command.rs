// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::commands::financials_command::ChangeDone::{Changed, Unchanged};
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use masq_lib::messages::{
    CustomQueries, CustomQueryResult, FirmQueryResult, RangeQuery, TopRecordsConfig,
    UiFinancialStatistics, UiFinancialsRequest, UiFinancialsResponse, UiPayableAccount,
    UiReceivableAccount,
};
use masq_lib::shared_schema::common_validators::validate_non_zero_u16;
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
const TOP_ARG_HELP: &str = "Returns a subset of the first N records (or fewer, if only a few exist) from both payable and receivable";
const PAYABLE_ARG_HELP: &str = "Forms a detailed query about payable records by specifying two ranges, one for their age in seconds and another for their balance in MASQs (decimal numbers are supported, allowing Gwei precision). The desirable format of those values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const RECEIVABLE_ARG_HELP: &str = "Forms a detailed query about receivable records by specifying two ranges, one for their age in seconds and another for their balance in MASQs (decimal numbers are supported, allowing Gwei precision). The desirable format of those values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>";
const NO_STATS_ARG_HELP: &str = "Disables statistics that displays by default, containing totals of paid and unpaid money from the perspective of debtors and creditors. This argument is not accepted alone and must be placed before other arguments";
const GWEI_HELP: &str =
    "Orders rendering amounts of money in Gwei of MASQ instead of whole MASQs as the default";
const SORTED_HELP: &str = "Allows a choice of parameter by which the returned records are sorted. This option works only together with the '--top' argument. Possible values: 'balance' or 'age', but 'balance' is defaulted and so hidden";
const WALLET_ADDRESS_LENGTH: usize = 42;

#[derive(Debug, PartialEq)]
pub struct FinancialsCommand {
    stats_required: bool,
    top_records_opt: Option<TopRecordsConfig>,
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
                .validator(validate_non_zero_u16),
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
                .value_name("RECEIVABLE")
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
                .short("n")
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
        .arg(
            Arg::with_name("sorted")
                .help(SORTED_HELP)
                .value_name("SORTED")
                .long("sorted")
                .short("s")
                .case_insensitive(false)
                .default_value_if("top", None, "balance")
                .possible_values(&["balance", "age"])
                .required(false),
        )
        .groups(&[
            ArgGroup::with_name("no-stats-requirement-group")
                .arg("no-stats")
                .requires("all-queries"),
            ArgGroup::with_name("top-records-conflicting-args")
                .args(&["top"])
                .conflicts_with("custom-queries")
                .requires("sorted"),
            ArgGroup::with_name("sorted-conflicting-args")
                .arg("sorted")
                .conflicts_with("custom-queries"),
            ArgGroup::with_name("all-queries")
                .args(&["receivable", "payable", "top"])
                .multiple(true),
            ArgGroup::with_name("custom-queries")
                .args(&["payable", "receivable"])
                .multiple(true),
        ])
}

impl Command for FinancialsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiFinancialsRequest {
            stats_required: self.stats_required,
            top_records_opt: self.top_records_opt.clone(),
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
                //TODO you can think of a way how to format it without unnecessary leading blank lines
                let stdout = context.stdout();
                if let Some(stats) = response.stats_opt {
                    self.process_financial_status(stdout, stats, gwei_flag)
                };
                //TODO what about making it more obvious these are mutual exclusive disregard the Clap's safe limitation?
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
        fn rearrange_range_query_output<T>(
            outputs: Option<(Option<RangeQuery<T>>, Option<UsersLiteralRangeDefinition>)>,
        ) -> (Option<RangeQuery<T>>, Option<UsersLiteralRangeDefinition>) {
            if let Some(x) = outputs {
                x
            } else {
                (None, None)
            }
        }

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
                    let (payable_opt, user_payable_format_opt) =
                        rearrange_range_query_output(payable_opt);
                    let (receivable_opt, user_receivable_format_opt) =
                        rearrange_range_query_output(receivable_opt);
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

    fn parse_top_records_arg(matches: &ArgMatches) -> Option<TopRecordsConfig> {
        matches.value_of("top").map(|str| TopRecordsConfig {
            count: str
                .parse::<u16>()
                .expect("top records count not properly validated"),
            sorted_by: matches
                .value_of("sorted")
                .expect("should be required and defaulted")
                .try_into()
                .expect("Clap did not catch invalid value"),
        })
    }

    fn parse_range_query_arg<
        'a,
        T: FromStr<Err = ParseIntError> + From<u32> + CheckedMul + Display + MaxValue,
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
            eprintln!("min: {}, max {}",min_amount_str,max_amount_str);
            (
                Some(RangeQuery {
                    min_age_s: min_age,
                    max_age_s: max_age,
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
            PayableHeadings(vec!["#", "Wallet", "Age [s]", balance, "Pending tx"], gwei),
            ReceivableHeadings(vec!["#", "Wallet", "Age [s]", balance], gwei),
        )
    }

    fn convert_masq_from_gwei_and_dress_well<T>(gwei: T) -> String
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
            Self::convert_masq_from_gwei_and_dress_well(gwei)
        }
    }

    fn financial_status_totals_title(stdout: &mut dyn Write, gwei: bool) {
        short_writeln!(
            stdout,
            "Financial status totals in {}\n",
            Self::print_gwei_or_masq_unit_type(gwei)
        );
    }

    fn title_for_tops(&self, stdout: &mut dyn Write, distinguished: &str) {
        Self::triple_blank_line(stdout);
        let requested_count = self.top_records_opt.as_ref().expectv("requested count");
        short_writeln!(
            stdout,
            "Top {} {} accounts\n",
            requested_count.count,
            distinguished
        )
    }

    fn width_precise_calculation(
        headings: &dyn Headings,
        accounts: &[&dyn WidthInfo],
    ) -> Vec<usize> {
        let headings_widths = Self::widths_of_dynamical_headings(headings.words());
        let values_widths = Self::figure_out_max_widths(accounts, headings.is_gwei());
        Self::yield_bigger_values_from_vecs(headings_widths.len(), headings_widths, values_widths)
    }

    fn widths_of_dynamical_headings(headings: &[&str]) -> Vec<usize> {
        headings
            .iter()
            .filter(|phrase| **phrase != "Wallet")
            .map(|phrase| phrase.len())
            .collect()
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
        let optimal_widths =
            Self::width_precise_calculation(headings, &Self::prepare_trait_objects(&accounts));
        Self::write_payable_headings(stdout, headings.words(), &optimal_widths);
        let mut ordinal_number = 0_usize;
        accounts.iter().for_each(|account| {
            ordinal_number += 1;
            Self::render_single_payable(
                stdout,
                account,
                &optimal_widths,
                ordinal_number,
                headings.is_gwei(),
            )
        });
    }

    fn write_payable_headings(stdout: &mut dyn Write, headings: &[&str], optimal_widths: &[usize]) {
        short_writeln!(
            stdout,
            "{:<ordinal_num_width$}   {:<wallet_width$}   {:<age_width$}   {:<balance_width$}   {:<hash_width$}",
            headings[0],
            headings[1],
            headings[2],
            headings[3],
            headings[4],
            ordinal_num_width = optimal_widths[0],
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = optimal_widths[1],
            balance_width = optimal_widths[2],
            hash_width = optimal_widths[3]
        )
    }

    fn render_single_payable(
        stdout: &mut dyn Write,
        account: &UiPayableAccount,
        optimal_widths: &[usize],
        ordinal_num: usize,
        gwei: bool,
    ) {
        //TODO we could have a tailored macro to use the same format in the headings and here
        short_writeln!(
            stdout,
            "{:<ordinal_num_width$}   {:wallet_width$}   {:<age_width$}   {:<balance_width$}   {:<hash_width$}",
            ordinal_num,
            account.wallet,
            account.age.separate_with_commas(),
            Self::process_gwei_into_right_format(account.balance_gwei, gwei),
            if let Some(hash) = &account.pending_payable_hash_opt {
                hash.as_str()
            } else {
                "None"
            },
            ordinal_num_width = optimal_widths[0],
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = optimal_widths[1],
            balance_width = optimal_widths[2],
            hash_width = optimal_widths[3]
        )
    }

    fn render_receivable(
        &self,
        stdout: &mut dyn Write,
        accounts: Vec<UiReceivableAccount>,
        headings: &ReceivableHeadings,
    ) {
        let optimal_widths =
            Self::width_precise_calculation(headings, &Self::prepare_trait_objects(&accounts));
        Self::write_receivable_headings(stdout, headings.words(), &optimal_widths);
        let mut ordinal_number = 0_usize;
        accounts.iter().for_each(|account| {
            ordinal_number += 1;
            Self::render_single_receivable(
                stdout,
                account,
                &optimal_widths,
                ordinal_number,
                headings.is_gwei(),
            )
        });
    }

    fn write_receivable_headings(
        stdout: &mut dyn Write,
        headings: &[&str],
        optimal_widths: &[usize],
    ) {
        short_writeln!(
            stdout,
            "{:<ordinal_number$}   {:wallet_width$}   {:<age_width$}   {:<balance_width$}",
            headings[0],
            headings[1],
            headings[2],
            headings[3],
            ordinal_number = optimal_widths[0],
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = optimal_widths[1],
            balance_width = optimal_widths[2],
        );
    }

    fn render_single_receivable(
        stdout: &mut dyn Write,
        account: &UiReceivableAccount,
        optimal_widths: &[usize],
        ordinal_number: usize,
        gwei: bool,
    ) {
        short_writeln!(
            stdout,
            "{:<ordinal_number$}   {:wallet_width$}   {:<age_width$}   {:<balance_width$}",
            ordinal_number,
            account.wallet,
            account.age.separate_with_commas(),
            Self::process_gwei_into_right_format(account.balance_gwei, gwei),
            ordinal_number = optimal_widths[0],
            wallet_width = WALLET_ADDRESS_LENGTH,
            age_width = optimal_widths[1],
            balance_width = optimal_widths[2],
        )
    }

    fn title_for_custom_query(
        stdout: &mut dyn Write,
        distinguished: &str,
        user_written_ranges: &UsersLiteralRangeDefinition,
    ) {
        let processed = Self::correct_users_writing_if_needed(user_written_ranges);
        let (time, amounts) = processed.value();
        Self::triple_blank_line(stdout);
        short_writeln!(
            stdout,
            "Specific {} query: {} sec {} MASQ\n",
            distinguished,
            time,
            amounts
        )
    }

    //TODO eliminate this with regex
    // ((-?)0*(\d+?)(\.[0-9]*)?0*$)|UNLIMITED    ???
    // here I could match against empty string and then to choose "unlimited"
    fn correct_users_writing_if_needed(
        user_ranges: &UsersLiteralRangeDefinition,
    ) -> ChangeDone<(String, String)> {
        todo!()


        // fn apply_care(str: &String) -> Option<String> {
        //     fn front_care(str: &String, decimal_dot_position: Option<usize>) -> String {
        //         fn count_leading_zeros(str: &str) -> (usize, bool) {
        //             str.chars().fold((0, true), |acc, char| {
        //                 if acc.1 {
        //                     if char == '0' {
        //                         (acc.0 + 1, true)
        //                     } else {
        //                         (acc.0, false)
        //                     }
        //                 } else {
        //                     acc
        //                 }
        //             })
        //         }
        //         let leading_zeros = count_leading_zeros(str.as_str());
        //         str.chars()
        //             .skip(if leading_zeros.0 == 0 {
        //                 0
        //             } else {
        //                 leading_zeros.0
        //                     - if let Some(idx) = decimal_dot_position {
        //                         if (idx - leading_zeros.0) == 0 {
        //                             1
        //                         } else {
        //                             0
        //                         }
        //                     } else if leading_zeros.0 == str.len() {
        //                         1
        //                     } else {
        //                         0
        //                     }
        //             })
        //             .collect()
        //     }
        //     fn make_decision(after_care: String, before: &String) -> Option<String> {
        //         if after_care.len() != before.len() {
        //             Some(after_care)
        //         } else {
        //             None
        //         }
        //     }
        //     if let Some(idx) = str.chars().position(|char| char == '.') {
        //         let after_care = front_care(str, Some(idx))
        //             .chars()
        //             .rev()
        //             .skip_while(|char| *char == '0')
        //             .collect::<String>()
        //             .chars()
        //             .rev()
        //             .collect::<String>();
        //         if after_care.len() != str.len() {
        //             Some(after_care)
        //         } else {
        //             None
        //         }
        //     } else {
        //         let after_care = front_care(str, None);
        //         make_decision(after_care, str)
        //     }
        // }
        //
        // let ((time_min, time_max), (amount_min, amount_max)) = user_ranges;
        // match (
        //     apply_care(time_min),
        //     apply_care(time_max),
        //     apply_care(amount_min),
        //     apply_care(amount_max),
        // ) {
        //     (None, None, None, None) => Unchanged((
        //         format!("{}-{}", time_min, time_max),
        //         format!("{}-{}", amount_min, amount_max),
        //     )),
        //     (a, b, c, d) => Changed((
        //         format!(
        //             "{}-{}",
        //             a.unwrap_or_else(|| time_min.to_string()),
        //             b.unwrap_or_else(|| time_max.to_string())
        //         ),
        //         format!(
        //             "{}-{}",
        //             c.unwrap_or_else(|| amount_min.to_string()),
        //             d.unwrap_or_else(|| amount_max.to_string())
        //         ),
        //     )),
        // }
    }

    fn no_records_found<F>(stdout: &mut dyn Write, headings: &[&str], write_headings: F)
    where
        F: Fn(&mut dyn Write, &[&str], &[usize]),
    {
        let headings_widths = Self::widths_of_dynamical_headings(headings);
        write_headings(stdout, headings, &headings_widths);
        short_writeln!(stdout, "\nNo records found",)
    }

    fn figure_out_max_widths(records: &[&dyn WidthInfo], is_gwei: bool) -> Vec<usize> {
        let cell_count = records[0].widths(is_gwei).len();
        let init = vec![0_usize; cell_count];
        let widths_except_ordinal_num = records.iter().fold(init, |acc, record| {
            let cells = record.widths(is_gwei);
            Self::yield_bigger_values_from_vecs(cell_count, acc, cells)
        });
        let mut result = vec![records.len().to_string().len()];
        result.extend(widths_except_ordinal_num);
        result
    }

    fn yield_bigger_values_from_vecs(
        cell_count: usize,
        first: Vec<usize>,
        second: Vec<usize>,
    ) -> Vec<usize> {
        (0..cell_count).fold(vec![], |acc_inner, idx| {
            plus(acc_inner, first[idx].max(second[idx]))
        })
    }

    fn count_length_with_comma_separators<N: Display>(value: N, is_plain_integer: bool) -> usize {
        fn add_in_commas_count(integer_length: usize) -> usize {
            let triple_chars = integer_length / 3;
            let possible_reminder = integer_length % 3;
            if possible_reminder == 0 {
                triple_chars * 3 + triple_chars - 1
            } else {
                triple_chars * 3 + possible_reminder + triple_chars
            }
        }
        let string_like = value.to_string();
        let gross_length = string_like.len();
        let is_negative = &string_like[0..=0] == "-";
        let unsigned_num_length = if is_negative {
            gross_length - 1
        } else {
            gross_length
        };
        let unsigned_processed = if is_plain_integer {
            add_in_commas_count(unsigned_num_length)
        } else {
            if unsigned_num_length <= 7 {
                return if !is_negative {
                    6 //means '< 0.01'
                } else {
                    13 //means '-0.01 < x < 0'
                };
            } else if unsigned_num_length == 8 {
                4
            } else if unsigned_num_length == 9 {
                4
            } else {
                let integer_part_length = unsigned_num_length - 9;
                add_in_commas_count(integer_part_length) + 3
            }
        };
        unsigned_processed + if !is_negative { 0 } else { 1 }
    }

    fn triple_blank_line(stdout: &mut dyn Write) {
        short_writeln!(stdout, "\n\n")
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
    fn widths(&self, is_gwei: bool) -> Vec<usize>;
}

impl WidthInfo for UiPayableAccount {
    fn widths(&self, is_gwei: bool) -> Vec<usize> {
        vec![
            FinancialsCommand::count_length_with_comma_separators(self.age, true),
            FinancialsCommand::count_length_with_comma_separators(self.balance_gwei, is_gwei),
            if let Some(transaction_hash) = &self.pending_payable_hash_opt {
                transaction_hash.len()
            } else {
                0
            },
        ]
    }
}

impl WidthInfo for UiReceivableAccount {
    fn widths(&self, is_gwei: bool) -> Vec<usize> {
        vec![
            FinancialsCommand::count_length_with_comma_separators(self.age, true),
            FinancialsCommand::count_length_with_comma_separators(self.balance_gwei, is_gwei),
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
        + CheckedMul
        + MaxValue,
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
            "Broken code: Clap validation should have caught this overflow of {} earlier",
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

fn envelope_for_extract_masq_and_return_gwei_str(
    range_str: &str,
) -> Result<(String, Option<String>), String> {
    let regex = Regex::new("((-?\\d+\\.?\\d*)\\s*-\\s*(-?\\d+\\.?\\d*))|(-?\\d+\\.?\\d*)$")
        .expect("wrong regex");
    extract_masq_and_return_gwei_str(&regex, range_str)
}

fn extract_masq_and_return_gwei_str(
    regex: &Regex,
    range_str: &str,
) -> Result<(String, Option<String>), String> {
    match regex.captures(range_str).map(|captures| {
        let fetch_group = |idx: usize| captures.get(idx).map(|catch| catch.as_str().to_owned());
        match (fetch_group(2), fetch_group(3)) {
            (Some(second), Some(third)) => (Some(second), Some(third)),
            (None, None) => match fetch_group(4) {
                Some(fourth) => (Some(fourth), None),
                None => todo!(),
            },
            (first, second) => todo!(),
        }
    }) {
        Some((Some(first), Some(second))) => Ok((first, Some(second))),
        Some((Some(first), None)) => Ok((first, None)),
        _ => Err("Second range in improper format".to_string()),
    }
}

pub fn parse_masq_range_to_gwei<N>(range_str: &str) -> Result<(N, N, String, String), String>
where
    N: FromStr<Err = ParseIntError> + From<u32> + Mul<Output = N> + CheckedMul + Display + MaxValue,
{
    eprintln!("range str: {}", range_str);
    let (first, second_opt) = envelope_for_extract_masq_and_return_gwei_str(range_str)?;
    Ok((
        process_optionally_fragmentary_number(&first)?,
        if let Some(second) = second_opt.as_ref() {
            process_optionally_fragmentary_number(second)?
        } else {
            N::max()
        },
        first,
        second_opt.unwrap_or(String::from("UNLIMITED")), //TODO could be an empty string
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

pub trait MaxValue {
    fn max() -> Self;
}

impl MaxValue for i64 {
    fn max() -> Self {
        i64::MAX
    }
}

impl MaxValue for u64 {
    fn max() -> Self {
        u64::MAX
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
        CustomQueryResult, FirmQueryResult, ToMessageBody, TopRecordsSorting,
        UiFinancialStatistics, UiFinancialsResponse, UiPayableAccount, UiReceivableAccount,
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
            "Returns a subset of the first N records (or fewer, if only a few exist) from both payable and receivable"
        );
        assert_eq!(PAYABLE_ARG_HELP,"Forms a detailed query about payable records by specifying two ranges, one for their age in seconds and another for their balance in MASQs (decimal numbers are supported, allowing Gwei precision). The desirable format of those values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>");
        assert_eq!(RECEIVABLE_ARG_HELP,"Forms a detailed query about receivable records by specifying two ranges, one for their age in seconds and another for their balance in MASQs (decimal numbers are supported, allowing Gwei precision). The desirable format of those values is <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>");
        assert_eq!(NO_STATS_ARG_HELP,"Disables statistics that displays by default, containing totals of paid and unpaid money from the perspective of debtors and creditors. This argument is not accepted alone and must be placed before other arguments");
        assert_eq!(
            GWEI_HELP,
            "Orders rendering amounts of money in Gwei of MASQ instead of whole MASQs as the default"
        );
        assert_eq!(SORTED_HELP, "Allows a choice of parameter by which the returned records are sorted. This option works only together with the '--top' argument. Possible values: 'balance' or 'age', but 'balance' is defaulted and so hidden");
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
    fn command_factory_everything_demanded_with_top_records() {
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
            custom_query_records_opt: None,
        }
        .tmb(0)));
        let subject = factory
            .make(&array_of_borrows_to_vec(&[
                "financials",
                "--top",
                "10",
                "--gwei",
            ]))
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn command_factory_everything_demanded_with_custom_queries() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 0,
                total_paid_payable_gwei: 1111,
                total_unpaid_receivable_gwei: 2222,
                total_paid_receivable_gwei: 3333,
            }),
            top_records_opt: None,
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: None,
                receivable_opt: None,
            }),
        }
        .tmb(0)));
        let subject = factory
            .make(&array_of_borrows_to_vec(&[
                "financials",
                "--payable",
                "200-450|480000-158000008",
                "--receivable",
                "5000-10000|0.003000000-5.600070000",
                "--gwei",
            ]))
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn command_factory_supplied_big_masq_values_are_not_fatal_for_non_decimal_values() {
        let factory = CommandFactoryReal::new();
        let result = factory
            .make(&array_of_borrows_to_vec(&[
                "financials",
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
    fn command_factory_supplied_big_masq_values_are_not_fatal_for_decimal_values() {
        let factory = CommandFactoryReal::new();
        let result = factory
            .make(&array_of_borrows_to_vec(&[
                "financials",
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
    fn command_factory_no_stats_arg_is_forbidden_if_no_other_arg_present() {
        let factory = CommandFactoryReal::new();

        let result = factory.make(&array_of_borrows_to_vec(&["financials", "--no-stats"]));

        let err = match result {
            Ok(_) => panic!("we expected error but got ok"),
            Err(CommandFactoryError::CommandSyntax(err_msg)) => err_msg,
            Err(e) => panic!("we expected CommandSyntax error but got: {:?}", e),
        };
        assert!(
            err.contains("The following required arguments were not provided:"),
            "{}",
            err
        );
        assert!(err.contains(
            "financials <--receivable <RECEIVABLE>|--payable <PAYABLE>|--top <TOP>> <--no-stats>"
        ),"{}",err);
    }

    fn top_records_mutual_exclusivity_assertion(args: &[&str], err_msg_first_part: &str) {
        let factory = CommandFactoryReal::new();

        let result = factory.make(&array_of_borrows_to_vec(args));

        let err = match result {
            Ok(_) => panic!("we expected error but got ok"),
            Err(CommandFactoryError::CommandSyntax(err_msg)) => err_msg,
            Err(e) => panic!("we expected CommandSyntax error but got: {:?}", e),
        };
        assert!(err.contains(err_msg_first_part), "{}", err);
        assert!(err.contains("financials <--receivable <RECEIVABLE>|--payable <PAYABLE>|--top <TOP>> <--payable <PAYABLE>|--receivable <RECEIVABLE>> <--sorted <SORTED>> <--top <TOP>>"),"{}",err)
    }

    #[test]
    fn command_factory_top_records_and_payable_custom_query_are_mutually_exclusive() {
        top_records_mutual_exclusivity_assertion(&[
            "financials",
            "--top",
            "15",
            "--payable",
            "5-100|600-7000",
        ],
"The argument '--payable <PAYABLE>' cannot be used with one or more of the other specified arguments",
        )
    }

    #[test]
    fn command_factory_top_records_and_receivable_custom_query_are_mutually_exclusive() {
        top_records_mutual_exclusivity_assertion(&[
            "financials",
            "--top",
            "15",
            "--receivable",
            "5-100|600-7000",
        ],"The argument '--receivable <RECEIVABLE>' cannot be used with one or more of the other specified arguments")
    }

    #[test]
    fn sorted_arg_can_be_combined_with_top_records_only() {
        let factory = CommandFactoryReal::new();

        let result = factory.make(&array_of_borrows_to_vec(&[
            "financials",
            "--receivable",
            "5-100|600-7000",
            "--sorted",
            "age",
        ]));

        let err = match result {
            Ok(_) => panic!("we expected error but got ok"),
            Err(CommandFactoryError::CommandSyntax(err_msg)) => err_msg,
            Err(e) => panic!("we expected CommandSyntax error but got: {:?}", e),
        };
        assert!(err.contains("The argument '--receivable <RECEIVABLE>' cannot be used with one or more of the other specified arguments"),"{}",err);
        assert!(err.contains("financials <--receivable <RECEIVABLE>|--payable <PAYABLE>|--top <TOP>> <--payable <PAYABLE>|--receivable <RECEIVABLE>> <--sorted <SORTED>>"),"{}",err)
    }

    #[test]
    fn financials_command_allows_shorthands_including_top_records() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let irrelevant_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: None,
        };
        let args =
            array_of_borrows_to_vec(&["financials", "-g", "-t", "123", "-s", "balance", "-n"]);
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
                    top_records_opt: Some(TopRecordsConfig {
                        count: 123,
                        sorted_by: TopRecordsSorting::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[test]
    fn financials_command_allows_shorthands_including_custom_query() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let irrelevant_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: None,
        };
        let args = array_of_borrows_to_vec(&[
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
    fn financials_command_top_records_sorted_by_age_instead_of_balance() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let irrelevant_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: None,
        };
        let args =
            array_of_borrows_to_vec(&["financials", "--no-stats", "--top", "7", "--sorted", "age"]);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(irrelevant_response.tmb(31)));
        let subject = FinancialsCommand::new(&args).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {
                    stats_required: false,
                    top_records_opt: Some(TopRecordsConfig {
                        count: 7,
                        sorted_by: TopRecordsSorting::Age
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
    }

    #[test]
    fn parse_top_records_arg_with_sorted_defaulted_to_balance() {
        let args = array_of_borrows_to_vec(&["financials", "--top", "11"]);
        let matches = financials_subcommand().get_matches_from_safe(args).unwrap();

        let result = FinancialsCommand::parse_top_records_arg(&matches);

        assert_eq!(
            result,
            Some(TopRecordsConfig {
                count: 11,
                sorted_by: TopRecordsSorting::Balance
            })
        )
    }

    #[test]
    fn sorted_have_just_two_possible_values() {
        let args =
            array_of_borrows_to_vec(&["financials", "--top", "11", "--sorted", "upside-down"]);

        let result = financials_subcommand()
            .get_matches_from_safe(args)
            .unwrap_err();

        assert!(
            result
                .message
                .contains("'upside-down' isn't a valid value for '--sorted <SORTED>'"),
            "{}",
            result
        );
        assert!(
            result.message.contains("[possible values: age, balance]"),
            "{}",
            result
        )
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
                            min_age_s: 5000,
                            max_age_s: 10000,
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
                            min_age_s: 5000,
                            max_age_s: 10000,
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
                \n\
                Unpaid and pending payable:       1.16\n\
                Paid payable:                     0.07\n\
                Unpaid receivable:                -0.05\n\
                Paid receivable:                  1,278.76\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[derive(Clone)]
    struct TestAccount {
        a: usize,
        b: usize,
        c: usize,
    }

    impl WidthInfo for TestAccount {
        fn widths(&self, is_gwei: bool) -> Vec<usize> {
            vec![self.a, self.b, self.c]
        }
    }

    #[test]
    fn figure_out_max_widths_works() {
        let mut vec_of_accounts = vec![
            TestAccount { a: 5, b: 2, c: 3 },
            TestAccount { a: 4, b: 6, c: 2 },
            TestAccount { a: 1, b: 4, c: 7 },
        ];
        //filling being useful to reach an ordinal number of an account with more than just one digit, here three digits
        vec_of_accounts.append(&mut vec![TestAccount { a: 0, b: 0, c: 0 }; 100]);

        let to_inspect = vec_of_accounts
            .iter()
            .map(|each| each as &dyn WidthInfo)
            .collect::<Vec<&dyn WidthInfo>>();

        let result = FinancialsCommand::figure_out_max_widths(&to_inspect, false);

        assert_eq!(result, vec![3, 5, 6, 7])
    }

    #[test]
    fn count_length_with_comma_separators_works_for_integers_and_exact_triples() {
        let number = 200_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, true);

        assert_eq!(result, 11)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_integers_and_incomplete_triples() {
        let number = 12_200_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, true);

        assert_eq!(result, 14)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_mask_format_a_few_thousandths_of_mask() {
        let number = 4_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 6) //means '< 0.01'
    }

    #[test]
    fn count_length_with_comma_separators_works_for_mask_format_a_few_hundredths_of_mask() {
        let number = 80_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 4)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_masq_format_a_few_tenths_of_masq() {
        let number = 200_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 4)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_masq_and_complete_triples() {
        let number = 456_456_200_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 10)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_masq_format_and_incomplete_triples() {
        let number = 2_200_568_560_800_u64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 8)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_masq_negative_number() {
        let number = -2_200_568_560_800_i64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 9)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_masq_negative_number_smaller_than_one() {
        let number = -68_560_800_i64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 5)
    }

    #[test]
    fn count_length_with_comma_separators_works_for_masq_negative_number_smaller_than_resolution_of_rendered_masqs(
    ) {
        let number = -68_800_i64;

        let result = FinancialsCommand::count_length_with_comma_separators(number, false);

        assert_eq!(result, 13) //means '-0.01 < x < 0'
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
        expected = "Broken code: Clap validation should have caught this overflow of 40000000000000000000 earlier"
    )]
    fn parse_integer_overflow_indicates_broken_code() {
        let _: Result<u64, String> = parse_integer("40000000000000000000");
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
            top_records_opt: for_top_records.then_some(FirmQueryResult {
                payable: vec![
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 5645405400,
                        balance_gwei: 68843325667,
                        pending_payable_hash_opt: None,
                    },
                    UiPayableAccount {
                        wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                        age: 150000,
                        balance_gwei: 8,
                        pending_payable_hash_opt: Some(
                            "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                                .to_string(),
                        ),
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
            custom_query_records_opt: (!for_top_records).then_some(CustomQueryResult {
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
    fn financials_command_stats_and_top_records_default_units_as_masq() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(true);
        let args = array_of_borrows_to_vec(&["financials", "--top", "123"]);
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
                    top_records_opt: Some(TopRecordsConfig {
                        count: 123,
                        sorted_by: TopRecordsSorting::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(),
            "\
                Financial status totals in MASQ\n\
                \n\
                Unpaid and pending payable:       0.11\n\
                Paid payable:                     235.55\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  < 0.01\n\
                \n\
                \n\
                \n\
                Top 123 payable accounts\n\
                \n\
                #   Wallet                                       Age [s]         Balance [MASQ]   Pending tx                                                        \n\
                1   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   5,645,405,400   68.84            None                                                              \n\
                2   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000         < 0.01           0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Top 123 receivable accounts\n\
                \n\
                #   Wallet                                       Age [s]   Balance [MASQ]\n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   22,000    2,444.53      \n\
                2   0x8bA50675e590b545D2128905b89039256Eaa24F6   19,000    -328.12       \n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_stats_and_custom_query_demanded_default_units_as_masq() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(false);
        let args = array_of_borrows_to_vec(&[
            "financials",
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
        assert_eq!(stdout_arc.lock().unwrap().get_string(),
            "\
                Financial status totals in MASQ\n\
                \n\
                Unpaid and pending payable:       0.11\n\
                Paid payable:                     235.55\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  < 0.01\n\
                \n\
                \n\
                \n\
                Specific payable query: 0-350000 sec 0.005-9 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [MASQ]   Pending tx                                                        \n\
                1   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000   < 0.01           0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Specific receivable query: 5000-10000 sec 0.003-5.60007 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [MASQ]\n\
                \n\
                No records found\n"
            );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_statistics_and_top_records_with_gwei_precision() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(true);
        let args = array_of_borrows_to_vec(&["financials", "--top", "123", "--gwei"]);
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
                    top_records_opt: Some(TopRecordsConfig {
                        count: 123,
                        sorted_by: TopRecordsSorting::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(),
            "\
                Financial status totals in Gwei\n\
                \n\
                Unpaid and pending payable:       116,688,555\n\
                Paid payable:                     235,555,554,578\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  665,557\n\
                \n\
                \n\
                \n\
                Top 123 payable accounts\n\
                \n\
                #   Wallet                                       Age [s]         Balance [Gwei]   Pending tx                                                        \n\
                1   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   5,645,405,400   68,843,325,667   None                                                              \n\
                2   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000         8                0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Top 123 receivable accounts\n\
                \n\
                #   Wallet                                       Age [s]   Balance [Gwei]   \n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   22,000    2,444,533,124,512\n\
                2   0x8bA50675e590b545D2128905b89039256Eaa24F6   19,000    -328,123,256,546 \n"
            );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_statistics_and_custom_query_with_gwei_precision() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = response_with_stats_and_either_top_records_or_top_queries(false);
        let args = array_of_borrows_to_vec(&[
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
        assert_eq!(stdout_arc.lock().unwrap().get_string(), "\
                Financial status totals in Gwei\n\
                \n\
                Unpaid and pending payable:       116,688,555\n\
                Paid payable:                     235,555,554,578\n\
                Unpaid receivable:                0\n\
                Paid receivable:                  665,557\n\
                \n\
                \n\
                \n\
                Specific payable query: 0-350000 sec 0.005-9 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [Gwei]   Pending tx                                                        \n\
                1   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000   8                0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
                \n\
                \n\
                \n\
                Specific receivable query: 5000-10000 sec 0.000004-0.455 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [Gwei]\n\
                \n\
                No records found\n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn custom_query_balance_range_can_be_shorthanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: Some(vec![UiPayableAccount {
                    wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                    age: 150000,
                    balance_gwei: 1200000000000,
                    pending_payable_hash_opt: Some(
                        "0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e"
                            .to_string(),
                    ),
                }]),
                receivable_opt: Some(vec![UiReceivableAccount {
                    wallet: "0x8bA50675e590b545D2128905b89039256Eaa24F6".to_string(),
                    age: 45700,
                    balance_gwei: 5050330000,
                }]),
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--payable",
            "0-350000|5",
            "--receivable",
            "5000-10000|0.8",
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
                    custom_queries_opt: Some(CustomQueries {
                        payable_opt: Some(RangeQuery {
                            min_age_s: 0,
                            max_age_s: 350000,
                            min_amount_gwei: 5000000000,
                            max_amount_gwei: u64::MAX
                        }),
                        receivable_opt: Some(RangeQuery {
                            min_age_s: 5000,
                            max_age_s: 10000,
                            min_amount_gwei: 800000000,
                            max_amount_gwei: i64::MAX
                        })
                    })
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(),
           "\n\
            \n\
            \n\
            Specific payable query: 0-350000 sec 5-UNLIMITED MASQ\n\
            \n\
            #   Wallet                                       Age [s]   Balance [MASQ]   Pending tx                                                        \n\
            1   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   150,000   1,200.00         0x0290db1d56121112f4d45c1c3f36348644f6afd20b759b762f1dba9c4949066e\n\
            \n\
            \n\
            \n\
            Specific receivable query: 5000-10000 sec 0.8-UNLIMITED MASQ\n\
            \n\
            #   Wallet                                       Age [s]   Balance [MASQ]\n\
            1   0x8bA50675e590b545D2128905b89039256Eaa24F6   45,700    5.05          \n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_no_records_found_with_stats_and_top_records() {
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
            custom_query_records_opt: None,
        };
        let args = array_of_borrows_to_vec(&["financials", "--top", "10"]);
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
                    top_records_opt: Some(TopRecordsConfig {
                        count: 10,
                        sorted_by: TopRecordsSorting::Balance
                    }),
                    custom_queries_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\
|Financial status totals in MASQ
|
|Unpaid and pending payable:       < 0.01
|Paid payable:                     < 0.01
|Unpaid receivable:                < 0.01
|Paid receivable:                  < 0.01
|
|
|
|Top 10 payable accounts
|
|#   Wallet                                       Age [s]   Balance [MASQ]   Pending tx
|
|No records found
|
|
|
|Top 10 receivable accounts
|
|#   Wallet                                       Age [s]   Balance [MASQ]
|
|No records found\n"
                .lines()
                .map(|line| format!("{}\n", line.strip_prefix("|").unwrap()))
                .collect::<String>()
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_no_records_found_with_stats_and_custom_query() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: 116688,
                total_paid_payable_gwei: 55555,
                total_unpaid_receivable_gwei: 221144,
                total_paid_receivable_gwei: 66555,
            }),
            top_records_opt: None,
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: None,
                receivable_opt: None,
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
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
            stdout_arc.lock().unwrap().get_string(),
            "\
|Financial status totals in MASQ
|
|Unpaid and pending payable:       < 0.01
|Paid payable:                     < 0.01
|Unpaid receivable:                < 0.01
|Paid receivable:                  < 0.01
|
|
|
|Specific payable query: 0-400000 sec 355-6000 MASQ
|
|#   Wallet                                       Age [s]   Balance [MASQ]   Pending tx
|
|No records found
|
|
|
|Specific receivable query: 40000-80000 sec 111-10000 MASQ
|
|#   Wallet                                       Age [s]   Balance [MASQ]
|
|No records found"
                .lines()
                .map(|line| format!("{}\n", line.strip_prefix("|").unwrap()))
                .collect::<String>()
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_only_top_records_demanded() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: Some(FirmQueryResult {
                payable: vec![
                    UiPayableAccount {
                        wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                        age: 5405400,
                        balance_gwei: 644000000,
                        pending_payable_hash_opt: Some(
                            "0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638"
                                .to_string(),
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0xEA674fdac714fd979de3EdF0F56AA9716B198ec8".to_string(),
                        age: 28120444,
                        balance_gwei: 97524120,
                        pending_payable_hash_opt: None,
                    },
                ],
                receivable: vec![
                    UiReceivableAccount {
                        wallet: "0xaa22968a5263f165F014d3F21A443f10a116EDe0".to_string(),
                        age: 566668,
                        balance_gwei: -550,
                    },
                    UiReceivableAccount {
                        wallet: "0x6e250504DdfFDb986C4F0bb8Df162503B4118b05".to_string(),
                        age: 11111111,
                        balance_gwei: -4551012,
                    },
                ],
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
                    top_records_opt: Some(TopRecordsConfig {
                        count: 7,
                        sorted_by: TopRecordsSorting::Balance
                    }),
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
                \n\
                Top 7 payable accounts\n\
                \n\
                #   Wallet                                       Age [s]      Balance [MASQ]   Pending tx                                                        \n\
                1   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   5,405,400    0.64             0x3648c8b8c7e067ac30b80b6936159326d564dd13b7ae465b26647154ada2c638\n\
                2   0xEA674fdac714fd979de3EdF0F56AA9716B198ec8   28,120,444   0.09             None                                                              \n\
                \n\
                \n\
                \n\
                Top 7 receivable accounts\n\
                \n\
                #   Wallet                                       Age [s]      Balance [MASQ]\n\
                1   0xaa22968a5263f165F014d3F21A443f10a116EDe0   566,668      < 0.01        \n\
                2   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   11,111,111   -0.01 < x < 0 \n"
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
            stdout_arc.lock().unwrap().get_string(),
               "\n\
                \n\
                \n\
                Specific payable query: 3000-40000 sec 88-1000 MASQ\n\
                \n\
                #   Wallet                                       Age [s]     Balance [MASQ]   Pending tx                                                        \n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   4,445       9.89             0x5fe272ed1e941cc05fbd624ec4b1546cd03c25d53e24ba2c18b11feb83cd4581\n\
                2   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   70,000      < 0.01           None                                                              \n\
                3   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   6,089,909   < 0.01           None                                                              \n"
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
            stdout_arc.lock().unwrap().get_string(),
            "\n\
                \n\
                \n\
                Specific receivable query: 3000-40000 sec 66-980 MASQ\n\
                \n\
                #   Wallet                                       Age [s]     Balance [Gwei]\n\
                1   0x6e250504DdfFDb986C4F0bb8Df162503B4118b05   4,445       9,898,999,888 \n\
                2   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   70,000      708,090       \n\
                3   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   6,089,909   66,658        \n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_returned_big_gwei_values_do_not_affect_the_column_width_for_values_in_masqs() {
        let expected_response = UiFinancialsResponse {
            stats_opt: None,
            top_records_opt: None,
            custom_query_records_opt: Some(CustomQueryResult {
                payable_opt: Some(vec![UiPayableAccount {
                    wallet: "0xA884A2F1A5Ec6C2e499644666a5E6af97B966888".to_string(),
                    age: 70000,
                    balance_gwei: 3862654858809045,
                    pending_payable_hash_opt: None,
                }]),
                receivable_opt: Some(vec![UiReceivableAccount {
                    wallet: "0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440".to_string(),
                    age: 6089909,
                    balance_gwei: 66658454845151517,
                }]),
            }),
        };
        let args = array_of_borrows_to_vec(&[
            "financials",
            "--receivable",
            "3000-40000|88-1000",
            "--payable",
            "3000-40000|88-1000",
            "--no-stats",
        ]);
        let mut context = CommandContextMock::new().transact_result(Ok(expected_response.tmb(31)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = FinancialsCommand::new(&args).unwrap();

        let _ = subject.execute(&mut context).unwrap();

        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\n\
                \n\
                \n\
                Specific payable query: 3000-40000 sec 88-1000 MASQ\n\
                \n\
                #   Wallet                                       Age [s]   Balance [MASQ]   Pending tx\n\
                1   0xA884A2F1A5Ec6C2e499644666a5E6af97B966888   70,000    3,862,654.85     None      \n\
                \n\
                \n\
                \n\
                Specific receivable query: 3000-40000 sec 88-1000 MASQ\n\
                \n\
                #   Wallet                                       Age [s]     Balance [MASQ]\n\
                1   0x6DbcCaC5596b7ac986ff8F7ca06F212aEB444440   6,089,909   66,658,454.84 \n"
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
    fn validate_two_ranges_also_integers_are_acceptable_for_masqs_range() {
        let result = validate_two_ranges::<i64>("454-2000|2000-30000".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_one_side_negative_range_is_acceptable_for_masqs_range() {
        let result = validate_two_ranges::<i64>("454-2000|-2000-30000".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_both_side_negative_range_is_acceptable_for_masqs_range() {
        let result = validate_two_ranges::<i64>("454-2000|-2000--1000".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_with_misused_central_delimiter() {
        let result = validate_two_ranges::<i64>("45-500545-006".to_string());

        assert_eq!(
            result,
            Err("Central vertical delimiter misused".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_with_misused_range_delimiter() {
        let result = validate_two_ranges::<i64>("45+500|545+006".to_string());

        assert_eq!(result, Err("First range is formatted wrong".to_string()))
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_time() {
        let result = validate_two_ranges::<u64>("4545-2000|20000.0-30000.0".to_string());

        assert_eq!(result, Err("Both ranges must be ascending".to_string()))
    }

    #[test]
    fn validate_two_ranges_both_values_the_same_for_time() {
        let result = validate_two_ranges::<i64>("2000-2000|20000.0-30000.0".to_string());

        assert_eq!(result, Err("Both ranges must be ascending".to_string()))
    }

    #[test]
    fn validate_two_ranges_both_values_the_same_for_masqs() {
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
    fn validate_two_ranges_non_numeric_value_for_first_range() {
        let result = validate_two_ranges::<i64>("blah-1234|899-999".to_string());

        assert_eq!(
            result,
            Err("Non numeric value > blah <, all must be valid numbers".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_non_numeric_value_for_second_range() {
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
