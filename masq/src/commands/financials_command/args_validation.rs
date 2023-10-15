// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::financials_command::parsing_and_value_dressing::restricted::{
    parse_masq_range_to_gwei, parse_time_params,
};
use clap::{Command as ClapCommand, Arg, ArgGroup, Subcommand};
use masq_lib::shared_schema::common_validators::validate_non_zero_u16;
use num::CheckedMul;
use std::fmt::{Debug, Display};
use std::num::ParseIntError;
use std::str::FromStr;
use clap::builder::ValueRange;

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
    Subcommand::with_name("financials")
        .about(FINANCIALS_SUBCOMMAND_ABOUT)
        .arg(
            Arg::new("top")
                .help(TOP_ARG_HELP)
                .value_name("TOP")
                .long("top")
                .short("t")
                .required(false)
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .validator(validate_non_zero_u16),
        )
        .arg(
            Arg::new("payable")
                .help(PAYABLE_ARG_HELP)
                .value_name("PAYABLE")
                .long("payable")
                .short("p")
                .required(false)
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .validator(validate_two_ranges::<u64>),
        )
        .arg(
            Arg::new("receivable")
                .help(RECEIVABLE_ARG_HELP)
                .value_name("RECEIVABLE")
                .long("receivable")
                .short("r")
                .required(false)
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .validator(validate_two_ranges::<i64>),
        )
        .arg(
            Arg::new("no-stats")
                .help(NO_STATS_ARG_HELP)
                .value_name("NO-STATS")
                .long("no-stats")
                .short("n")
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .required(false),
        )
        .arg(
            Arg::new("gwei")
                .help(GWEI_HELP)
                .value_name("GWEI")
                .long("gwei")
                .short("g")
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1))
                .required(false),
        )
        .arg(
            Arg::new("ordered")
                .help(ORDERED_HELP)
                .value_name("ORDERED")
                .long("ordered")
                .short("o")
                .ignore_case(false)
                .default_value_if("top", None, "balance")
                .possible_values(&["balance", "age"])
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
                .conflicts_with("custom-queries")
                .requires("ordered"),
            ArgGroup::new("ordered-conflicts")
                .arg("ordered")
                .conflicts_with("custom-queries"),
        ])
}

fn validate_two_ranges<N>(two_ranges: String) -> Result<(), String>
where
    N: FromStr<Err = ParseIntError>
        + TryFrom<i64>
        + TryFrom<u64>
        + CheckedMul
        + Display
        + Copy
        + PartialOrd,
    i64: TryFrom<N>,
    u64: TryFrom<N>,
    <N as TryFrom<i64>>::Error: Debug,
    <i64 as TryFrom<N>>::Error: Debug,
{
    fn checked_split<'a>(
        str: &'a str,
        delim: char,
        err_msg_formatter: fn(&'a str) -> String,
    ) -> Result<(&'a str, &'a str), String> {
        let split_elems = str.split(delim).collect::<Vec<&str>>();
        if split_elems.len() != 2 {
            return Err(err_msg_formatter(str));
        }
        Ok((split_elems[0], split_elems[1]))
    }
    let (aga_range, balance_range) = checked_split(&two_ranges, '|', |wrong_input| {
        format!("Vertical delimiter | should be used between age and balance ranges and only there. Example: '1234-2345|3456-4567', not '{}'", wrong_input)
    })?;
    let (min_age_str, max_age_str) = checked_split(aga_range, '-', |wrong_input| {
        format!("Age range '{}' is formatted wrong", wrong_input)
    })?;
    let (min_age, max_age) = parse_time_params(min_age_str, max_age_str)?;
    let (min_amount, max_amount, _, _): (N, N, _, _) = parse_masq_range_to_gwei(balance_range)?;
    //Reasons why only a range input is allowed:
    //There is no use trying to check an exact age because of its all time moving nature.
    //The backend engine does the search always with a wei precision while at this end you cannot
    //pick values more precisely than as 1 gwei, so it's quite impossible to guess an exact value anyway.
    if min_age >= max_age || min_amount >= max_amount {
        Err(format!("Both ranges '{}' must be low to high", two_ranges))
    } else {
        Ok(())
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
    fn validate_two_ranges_with_decimal_part_longer_than_the_whole_gwei_range() {
        let result = validate_two_ranges::<i64>("454-2000|100-1000.000111222333".to_string());

        assert_eq!(result, Err("Value '1000.000111222333' exceeds the limit of maximally nine decimal digits (only gwei supported)".to_string()))
    }

    #[test]
    fn validate_two_ranges_with_decimal_part_fully_used_up() {
        let result = validate_two_ranges::<i64>("454-2000|100-1000.000111222".to_string());

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn validate_two_ranges_with_misused_central_delimiter() {
        let result = validate_two_ranges::<i64>("45-500545-006".to_string());

        assert_eq!(
            result,
            Err("Vertical delimiter | should be used between age and balance ranges and only there. \
             Example: '1234-2345|3456-4567', not '45-500545-006'".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_with_misused_range_delimiter() {
        let result = validate_two_ranges::<i64>("45+500|545+006".to_string());

        assert_eq!(
            result,
            Err("Age range '45+500' is formatted wrong".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_time() {
        let result = validate_two_ranges::<u64>("4545-2000|20000.0-30000.0".to_string());

        assert_eq!(
            result,
            Err("Both ranges '4545-2000|20000.0-30000.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_both_values_the_same_for_time() {
        let result = validate_two_ranges::<i64>("2000-2000|20000.0-30000.0".to_string());

        assert_eq!(
            result,
            Err("Both ranges '2000-2000|20000.0-30000.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_both_values_the_same_for_masqs() {
        let result = validate_two_ranges::<i64>("1000-2000|20000.0-20000.0".to_string());

        assert_eq!(
            result,
            Err("Both ranges '1000-2000|20000.0-20000.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_masqs_but_not_in_decimals() {
        let result = validate_two_ranges::<i64>("2000-4545|30.0-27.0".to_string());

        assert_eq!(
            result,
            Err("Both ranges '2000-4545|30.0-27.0' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_second_value_smaller_than_the_first_for_masqs_in_decimals() {
        let result = validate_two_ranges::<u64>("2000-4545|20.13-20.11".to_string());

        assert_eq!(
            result,
            Err("Both ranges '2000-4545|20.13-20.11' must be low to high".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_non_numeric_value_for_first_range() {
        let result = validate_two_ranges::<i64>("blah-1234|899-999".to_string());

        assert_eq!(
            result,
            Err("Non numeric value 'blah', it must be a valid integer".to_string())
        )
    }

    #[test]
    fn validate_two_ranges_non_numeric_value_for_second_range() {
        let result = validate_two_ranges::<i64>("1000-1234|7878.0-a lot".to_string());

        assert_eq!(
            result,
            Err("Balance range '7878.0-a lot' in improper format".to_string())
        )
    }
}
