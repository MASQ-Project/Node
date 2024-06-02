// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::TerminalWriter;
use clap::builder::{ArgPredicate, ValueRange};
use clap::{value_parser, Arg, ArgGroup, Command as ClapCommand};
use masq_lib::constants::{GWEI_IN_MASQ, MASQ_TOTAL_SUPPLY};
use masq_lib::messages::{RangeQuery, TopRecordsOrdering};
use masq_lib::short_writeln;
use num::ToPrimitive;
use regex::{Captures, Regex};
use std::fmt::Debug;
use std::io::Write;
use std::str::FromStr;

const FINANCIALS_SUBCOMMAND_ABOUT: &str =
    "Displays financial statistics of this Node. Only valid if Node is already running.";
const TOP_ARG_HELP: &str = "Fetches the top N records (or fewer) from both payable and receivable. The default order is decreasing by balance, but can be changed with the additional '--ordered' argument.";
const PAYABLE_ARG_HELP: &str = "Enables querying payable records by two specified ranges, one for the age in seconds and another for the balance in MASQs (use the decimal notation to achieve the desired gwei precision). \
 The correct format consists of two ranges separated by | as in the example <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>. Leaving out <MAX-BALANCE>, including the preceding hyphen, will default to maximum (2^64 - 1). If this \
  parameter is being set in the non-interactive mode, the value needs to be enclosed in quotes (single or double).";
const RECEIVABLE_ARG_HELP: &str = "Enables querying receivable records by two specified ranges, one for the age in seconds and another for the balance in MASQs (use the decimal notation to achieve the desired gwei precision). \
 The correct format consists of two ranges separated by | as in the example <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>. Leaving out <MAX-BALANCE>, including the preceding hyphen, will default to maximum (2^64 - 1). If this \
  parameter is being set in the non-interactive mode, the value needs to be enclosed in quotes (single or double).";
const NO_STATS_ARG_HELP: &str = "Disables statistics that display by default, containing totals of paid and unpaid money from the perspective of debtors and creditors. This argument is not accepted alone and must be placed \
 before other arguments.";
const GWEI_HELP: &str =
    "Orders money values rendering in gwei of MASQ instead of whole MASQs as the default.";
const ORDERED_HELP: &str = "Determines in what ordering the top records will be returned. This option works only with the '--top' argument.";

pub fn financials_subcommand() -> ClapCommand {
    ClapCommand::new("financials")
        .about(FINANCIALS_SUBCOMMAND_ABOUT)
        .arg(
            Arg::new("top")
                .help(TOP_ARG_HELP)
                .value_name("TOP")
                .long("top")
                .short('t')
                .required(false)
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .value_parser(value_parser!(NonZeroU16)),
        )
        .arg(
            Arg::new("payable")
                .help(PAYABLE_ARG_HELP)
                .value_name("PAYABLE")
                .long("payable")
                .short('p')
                .required(false)
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .value_parser(value_parser!(TwoRanges)),
        )
        .arg(
            Arg::new("receivable")
                .help(RECEIVABLE_ARG_HELP)
                .value_name("RECEIVABLE")
                .long("receivable")
                .short('r')
                .required(false)
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .value_parser(value_parser!(TwoRanges)),
        )
        .arg(
            Arg::new("no-stats")
                .help(NO_STATS_ARG_HELP)
                .value_name("NO-STATS")
                .long("no-stats")
                .short('n')
                .ignore_case(false)
                .num_args(ValueRange::new(0..=0))
                .required(false),
        )
        .arg(
            Arg::new("gwei")
                .help(GWEI_HELP)
                .value_name("GWEI")
                .long("gwei")
                .short('g')
                .ignore_case(false)
                .num_args(ValueRange::new(0..=0))
                .required(false),
        )
        .arg(
            Arg::new("ordered")
                .help(ORDERED_HELP)
                .value_name("ORDERED")
                .long("ordered")
                .short('o')
                .ignore_case(false)
                .default_value_if("top", ArgPredicate::IsPresent, "balance")
                .value_parser(value_parser!(TopRecordsOrdering))
                .required(false),
        )
        .groups(&[
            ArgGroup::new("at_least_one_query")
                .args(&["receivable", "payable", "top"])
                .multiple(true),
            ArgGroup::new("no-stats-requirement-group")
                .arg("no-stats")
                .requires("at_least_one_query"),
            ArgGroup::new("custom-queries")
                .args(&["payable", "receivable"])
                .multiple(true),
            ArgGroup::new("top-records-conflicts")
                .args(&["top"])
                .conflicts_with("custom-queries"),
            ArgGroup::new("ordered-conflicts")
                .arg("ordered")
                .conflicts_with("custom-queries"),
        ])
}

#[derive(Debug, PartialEq, Clone)]
pub struct NonZeroU16 {
    pub data: u16,
}

impl FromStr for NonZeroU16 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match u16::from_str(s) {
            Ok(value) if value != 0 => Ok(NonZeroU16 { data: value }),
            _ => Err(format!("Can't parse NonZeroU16 from '{}'", s)),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct TwoRanges {
    pub age_range: (u64, u64),
    pub gwei_range: (i128, Option<i128>),
}

impl FromStr for TwoRanges {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (age_range_str, balance_range_str) = Self::checked_split(&s, '|', |wrong_input| {
            format!("Vertical delimiter | should be used between age and balance ranges and only there. Example: '1234-2345|3456-4567', not '{}'", wrong_input)
        })?;
        let (min_age_str, max_age_str) = Self::checked_split(age_range_str, '-', |wrong_input| {
            format!("Age range '{}' is formatted wrong", wrong_input)
        })?;
        let age_range = Self::parse_time_params(min_age_str, max_age_str)?;
        Self::check_range(s, &age_range.0, &age_range.1)?;
        let amount_range = Self::parse_masq_range_to_gwei(balance_range_str)?;
        match amount_range.1 {
            Some(high) => Self::check_range(s, &amount_range.0, &high)?,
            None => Self::check_range(s, &amount_range.0, &(i64::MAX as i128))?,
        }
        Ok(TwoRanges {
            age_range,
            gwei_range: amount_range,
        })
    }
}

impl TwoRanges {
    pub fn try_convert_with_limit_u(&self, limit: i128) -> Result<RangeQuery<u64>, String> {
        let (age_low, age_high, amount_low, amount_high) = self.try_convert_with_limit(limit)?;
        Ok(RangeQuery {
            min_age_s: age_low,
            max_age_s: age_high,
            min_amount_gwei: amount_low as u64,
            max_amount_gwei: amount_high as u64,
        })
    }

    pub fn try_convert_with_limit_i(&self, limit: i128) -> Result<RangeQuery<i64>, String> {
        let (age_low, age_high, amount_low, amount_high) = self.try_convert_with_limit(limit)?;
        Ok(RangeQuery {
            min_age_s: age_low,
            max_age_s: age_high,
            min_amount_gwei: amount_low as i64,
            max_amount_gwei: amount_high as i64,
        })
    }

    fn try_convert_with_limit(&self, limit: i128) -> Result<(u64, u64, i128, i128), String> {
        let apply_limit = |candidate: i128| -> Result<i128, String> {
            if candidate <= limit {
                Ok(candidate)
            } else {
                Err(format!("Value '{}' exceeds the limit of maximally nine decimal digits (only gwei supported)", candidate))
            }
        };
        let amount_low = apply_limit(self.gwei_range.0)?;
        let amount_high = match self.gwei_range.1 {
            Some(ah) => apply_limit(ah)?,
            None => limit,
        };
        Ok((self.age_range.0, self.age_range.1, amount_low, amount_high))
    }

    fn checked_split(
        str: &str,
        delim: char,
        err_msg_formatter: fn(&str) -> String,
    ) -> Result<(&str, &str), String> {
        let split_elems = str.split(delim).collect::<Vec<&str>>();
        if split_elems.len() != 2 {
            return Err(err_msg_formatter(str));
        }
        Ok((split_elems[0], split_elems[1]))
    }

    fn parse_time_params(min_age_str: &str, max_age_str: &str) -> Result<(u64, u64), String> {
        Ok((
            Self::parse_integer_as_i128(min_age_str)? as u64,
            Self::parse_integer_as_i128(max_age_str)? as u64,
        ))
    }

    fn parse_integer_as_i128(str_gwei: &str) -> Result<i128, String> {
        str::parse::<i128>(str_gwei).map_err(|_| {
            format!(
                "Non numeric value '{}', it must be a valid integer",
                str_gwei
            )
        })
    }

    fn parse_masq_range_to_gwei(range_str: &str) -> Result<(i128, Option<i128>), String> {
        let regex = Regex::new(r#"^((-?\d+\.?\d*)\s*-\s*(-?\d+\.?\d*))|(-?\d+\.?\d*)$"#)
            .expect("wrong regex");
        let (first, second_opt) = Self::extract_individual_masq_values(range_str, regex)?;
        let first_numeral = Self::process_optionally_fractional_number(&first)?;
        let second_numeral_opt = match second_opt {
            None => None,
            Some(second) => Some(Self::process_optionally_fractional_number(&second)?),
        };
        Ok((first_numeral, second_numeral_opt))
    }

    fn check_range<T: PartialOrd>(s: &str, low: &T, high: &T) -> Result<(), String> {
        if low >= high {
            Err(format!("Both ranges '{}' must be low to high", s))
        } else {
            Ok(())
        }
    }

    fn process_optionally_fractional_number(num: &str) -> Result<i128, String> {
        const DIGITS_IN_BILLION: u32 = 9;
        fn all_digits_with_dot_removed(num: &str) -> String {
            num.chars().filter(|char| *char != '.').collect()
        }
        fn number_of_decimal_digits_unchecked(num: &str, dot_idx: usize) -> u32 {
            let int_part_plus_dot_length = dot_idx + 1;
            u32::try_from(num.chars().count() - int_part_plus_dot_length)
                .expect("previous check of maximally 9 decimal digits failed")
        }
        fn decimal_digits_count(num: &str, dot_idx: usize) -> Result<u32, String> {
            let decimal_digits_count = number_of_decimal_digits_unchecked(num, dot_idx);
            if decimal_digits_count <= DIGITS_IN_BILLION {
                Ok(decimal_digits_count)
            } else {
                Err(format!("Value '{}' exceeds the limit of maximally nine decimal digits (only gwei supported)", num))
            }
        }
        let decimal_shift_to_gwei = |parse_result: i128, exponent: u32| {
            let gwei_result = parse_result
                .checked_mul(i128::try_from(10_i64.pow(exponent)).expect("no fear"))
                .ok_or_else(|| {
                    format!(
                        "Amount bigger than the MASQ total supply: {}, total supply: {}",
                        num, MASQ_TOTAL_SUPPLY
                    )
                });
            match gwei_result {
                Err(e) => Err(e),
                Ok(gwei) => {
                    if gwei > (MASQ_TOTAL_SUPPLY as i128 * GWEI_IN_MASQ) {
                        Err(format!(
                            "Amount bigger than the MASQ total supply: {}, total supply: {}",
                            num, MASQ_TOTAL_SUPPLY
                        ))
                    } else {
                        Ok(gwei)
                    }
                }
            }
        };

        let dot_opt = num.chars().position(|char| char == '.');
        if let Some(dot_idx) = dot_opt {
            Self::check_right_dot_usage(num, dot_idx)?;
            let full_range_of_digits = all_digits_with_dot_removed(num);
            let all_digits_with_dot_removed_parsed =
                Self::parse_integer_as_i128(&full_range_of_digits)?;
            let decimal_digits_count = decimal_digits_count(num, dot_idx)?;
            decimal_shift_to_gwei(
                all_digits_with_dot_removed_parsed,
                DIGITS_IN_BILLION - decimal_digits_count,
            )
        } else {
            decimal_shift_to_gwei(Self::parse_integer_as_i128(num)?, DIGITS_IN_BILLION)
        }
    }

    fn check_right_dot_usage(num: &str, dot_idx: usize) -> Result<(), String> {
        if dot_idx == (num.len() - 1) {
            Err(format!(
                "Ending dot at decimal number, like here '{}', is unsupported",
                num
            ))
        } else if num.chars().filter(|char| *char == '.').count() != 1 {
            Err(format!("Misused decimal number dot delimiter at '{}'", num))
        } else {
            Ok(())
        }
    }

    fn handle_captures(captures: Captures) -> (Option<String>, Option<String>) {
        let fetch_group = |idx: usize| Self::single_capture(&captures, idx);
        match (fetch_group(2), fetch_group(3)) {
            (Some(second), Some(third)) => (Some(second), Some(third)),
            (None, None) => {
                let four = fetch_group(4).expect("the regex is wrong if it allows this panic");
                (Some(four), None)
            }
            (x, y) => {
                unreachable!(
                    "the regex was designed not to allow '{:?}' for the second and \
                     '{:?}' for the third capture group",
                    x, y
                )
            }
        }
    }

    fn extract_individual_masq_values(
        masq_in_range_str: &str,
        masq_values_in_range_regex: Regex,
    ) -> Result<(String, Option<String>), String> {
        match masq_values_in_range_regex
            .captures(masq_in_range_str)
            .map(Self::handle_captures)
        {
            Some((Some(first), Some(second))) => Ok((first, Some(second))),
            Some((Some(first), None)) => Ok((first, None)),
            _ => Err(format!(
                "Balance range '{}' in improper format",
                masq_in_range_str
            )),
        }
    }

    fn single_capture(captures: &Captures, idx: usize) -> Option<String> {
        captures.get(idx).map(|catch| catch.as_str().to_owned())
    }

    pub async fn title_for_custom_query<R>(
        stdout: &TerminalWriter,
        table_type: &str,
        range_query: RangeQuery<R>,
    ) where
        R: ToPrimitive,
    {
        short_writeln!(
            stdout,
            "Specific {} query: {} - {} sec old, {} - {} MASQ\n",
            table_type,
            range_query.min_age_s,
            range_query.max_age_s,
            Self::gwei_as_masq(range_query.min_amount_gwei),
            Self::gwei_as_masq(range_query.max_amount_gwei)
        )
    }

    fn gwei_as_masq<R>(gwei: R) -> String
    where
        R: ToPrimitive,
    {
        if gwei.to_i64().expect("Can't convert integer to i64") == i64::MAX {
            return "∞".to_string();
        }
        let gwei_f = gwei.to_f64().expect("Can't convert integer to float");
        let masq_f = gwei_f / (GWEI_IN_MASQ as f64);
        format!("{}", masq_f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            FINANCIALS_SUBCOMMAND_ABOUT,
            "Displays financial statistics of this Node. Only valid if Node is already running."
        );
        assert_eq!(
            TOP_ARG_HELP,
            "Fetches the top N records (or fewer) from both payable and receivable. The default order is decreasing by balance, but can be changed with the additional '--ordered' argument."
        );
        assert_eq!(PAYABLE_ARG_HELP, "Enables querying payable records by two specified ranges, one for the age in seconds and another for the balance in MASQs (use the decimal notation to achieve the desired gwei precision). \
            The correct format consists of two ranges separated by | as in the example <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>. Leaving out <MAX-BALANCE>, including the preceding hyphen, will default to maximum (2^64 - 1). \
            If this parameter is being set in the non-interactive mode, the value needs to be enclosed in quotes (single or double).");
        assert_eq!(RECEIVABLE_ARG_HELP, "Enables querying receivable records by two specified ranges, one for the age in seconds and another for the balance in MASQs (use the decimal notation to achieve the desired gwei precision). \
            The correct format consists of two ranges separated by | as in the example <MIN-AGE>-<MAX-AGE>|<MIN-BALANCE>-<MAX-BALANCE>. Leaving out <MAX-BALANCE>, including the preceding hyphen, will default to maximum (2^64 - 1). \
            If this parameter is being set in the non-interactive mode, the value needs to be enclosed in quotes (single or double).");
        assert_eq!(NO_STATS_ARG_HELP, "Disables statistics that display by default, containing totals of paid and unpaid money from the perspective of debtors and creditors. This argument is not accepted alone and must be placed \
                    before other arguments.");
        assert_eq!(
            GWEI_HELP,
            "Orders money values rendering in gwei of MASQ instead of whole MASQs as the default."
        );
        assert_eq!(ORDERED_HELP, "Determines in what ordering the top records will be returned. This option works only with the '--top' argument.");
    }

    #[test]
    fn from_str_for_nonzerou16_doesnt_like_bad_syntax() {
        let result = NonZeroU16::from_str("booga");

        assert_eq!(
            result,
            Err("Can't parse NonZeroU16 from 'booga'".to_string())
        )
    }

    #[test]
    fn from_str_for_nonzerou16_doesnt_like_zero() {
        let result = NonZeroU16::from_str("0");

        assert_eq!(result, Err("Can't parse NonZeroU16 from '0'".to_string()))
    }

    #[test]
    fn from_str_for_nonzerou16_doesnt_like_big_numbers() {
        let result = NonZeroU16::from_str("65536");

        assert_eq!(
            result,
            Err("Can't parse NonZeroU16 from '65536'".to_string())
        )
    }

    #[test]
    fn from_str_for_nonzerou16_happy_path() {
        let result = NonZeroU16::from_str("1024");

        assert_eq!(result, Ok(NonZeroU16 { data: 1024 }))
    }

    #[test]
    fn validate_two_ranges_also_integers_are_acceptable_for_masqs_range() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("454-2000|2000-30000");

        assert_eq!(
            result,
            Ok(TwoRanges {
                age_range: (454, 2000),
                gwei_range: (2_000_000_000_000, Some(30_000_000_000_000))
            })
        )
    }

    #[test]
    fn validate_two_ranges_one_side_negative_range_is_acceptable_for_masqs_range() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("454-2000|-2000-30000");

        assert_eq!(
            result,
            Ok(TwoRanges {
                age_range: (454, 2000),
                gwei_range: (-2_000_000_000_000, Some(30_000_000_000_000))
            })
        )
    }

    #[test]
    fn validate_two_ranges_both_side_negative_range_is_acceptable_for_masqs_range() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("454-2000|-2000--1000");

        assert_eq!(
            result,
            Ok(TwoRanges {
                age_range: (454, 2000),
                gwei_range: (-2_000_000_000_000, Some(-1_000_000_000_000))
            })
        )
    }

    #[test]
    fn validate_two_ranges_with_decimal_part_longer_than_the_whole_gwei_range() {
        let result: Result<TwoRanges, String> =
            TwoRanges::from_str("454-2000|100-1000.000111222333");

        assert_eq!(result, Err("Value '1000.000111222333' exceeds the limit of maximally nine decimal digits (only gwei supported)".to_string()))
    }

    #[test]
    fn validate_two_ranges_with_decimal_part_fully_used_up() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("454-2000|100-1000.000111222");

        assert_eq!(
            result,
            Ok(TwoRanges {
                age_range: (454, 2000),
                gwei_range: (100_000_000_000, Some(1_000_000_111_222))
            })
        )
    }

    #[test]
    fn validate_two_ranges_with_misused_central_delimiter() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("45-500545-006");

        assert_eq!(
            result,
            Err("Vertical delimiter | should be used between age and balance ranges and only there. \
             Example: '1234-2345|3456-4567', not '45-500545-006'".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_with_misused_range_delimiter() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("45+500|545+006");

        assert_eq!(
            result,
            Err("Age range '45+500' is formatted wrong".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_time() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("4545-2000|20000.0-30000.0");

        assert_eq!(
            result,
            Err("Both ranges '4545-2000|20000.0-30000.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_both_values_the_same_for_time() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("2000-2000|20000.0-30000.0");

        assert_eq!(
            result,
            Err("Both ranges '2000-2000|20000.0-30000.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_both_values_the_same_for_masqs() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("1000-2000|20000.0-20000.0");

        assert_eq!(
            result,
            Err("Both ranges '1000-2000|20000.0-20000.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_masqs_but_not_in_decimals() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("2000-4545|30.0-27.0");

        assert_eq!(
            result,
            Err("Both ranges '2000-4545|30.0-27.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_masqs_in_decimals() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("2000-4545|20.13-20.11");

        assert_eq!(
            result,
            Err("Both ranges '2000-4545|20.13-20.11' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_non_numeric_value_for_first_range() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("blah-1234|899-999");

        assert_eq!(
            result,
            Err("Non numeric value 'blah', it must be a valid integer".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_non_numeric_value_for_second_range() {
        let result: Result<TwoRanges, String> = TwoRanges::from_str("1000-1234|7878.0-a lot");

        assert_eq!(
            result,
            Err("Balance range '7878.0-a lot' in improper format".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_overflow_for_i128_is_detected() {
        let too_much: i128 = 1_000_000_000_000_000_000_000_000_000_000_000;
        let result: Result<TwoRanges, String> =
            TwoRanges::from_str(&format!("1000-1234|1234-{}", too_much));

        assert_eq!(
            result,
            Err(format!(
                "Amount bigger than the MASQ total supply: {}, total supply: {}",
                too_much, MASQ_TOTAL_SUPPLY
            ))
        )
    }

    #[test]
    fn validate_two_ranges_masq_value_too_high_is_caught() {
        let too_much = MASQ_TOTAL_SUPPLY + 1;
        let result: Result<TwoRanges, String> =
            TwoRanges::from_str(&format!("1000-1234|1234-{}", too_much));

        assert_eq!(
            result,
            Err(format!(
                "Amount bigger than the MASQ total supply: {}, total supply: {}",
                too_much, MASQ_TOTAL_SUPPLY
            ))
        )
    }

    #[test]
    fn process_optionally_fractional_number_dislikes_dot_as_the_last_char() {
        let result = TwoRanges::process_optionally_fractional_number("4556.");

        assert_eq!(
            result,
            Err("Ending dot at decimal number, like here '4556.', is unsupported".to_string())
        )
    }

    #[test]
    fn process_optionally_fractional_number_dislikes_more_than_one_dot() {
        let result = TwoRanges::process_optionally_fractional_number("45.056.000");

        assert_eq!(
            result,
            Err("Misused decimal number dot delimiter at '45.056.000'".to_string())
        )
    }

    #[test]
    #[should_panic(
        expected = "entered unreachable code: the regex was designed not to allow 'None' for the second and 'Some(\"ghi\")' for the third capture group"
    )]
    fn extract_individual_masq_values_regex_is_wrong() {
        let regex = Regex::new("(abc)?(def)?(ghi)").unwrap();

        let _ = TwoRanges::extract_individual_masq_values("ghi", regex);
    }
}
