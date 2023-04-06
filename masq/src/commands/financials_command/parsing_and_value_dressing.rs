// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::commands::financials_command) mod restricted {
    use crate::commands::financials_command::data_structures::restricted::UserOriginalTypingOfRanges;
    use masq_lib::constants::{MASQ_TOTAL_SUPPLY, WEIS_IN_GWEI};
    use masq_lib::utils::ExpectValue;
    use num::CheckedMul;
    use regex::{Captures, Regex};
    use std::any::type_name;
    use std::collections::VecDeque;
    use std::fmt::{Debug, Display};
    use std::num::{IntErrorKind, ParseIntError};
    use std::str::FromStr;
    use thousands::Separable;

    pub fn convert_masq_from_gwei_and_dress_well(balance_gwei: i64) -> String {
        const MASK_FOR_NON_SIGNIFICANT_DIGITS: i64 = 10_000_000;
        let balance_masq_int = (balance_gwei / WEIS_IN_GWEI as i64).abs();
        let balance_masq_frac = (balance_gwei % WEIS_IN_GWEI as i64).abs();
        let balance_masq_frac_trunc = balance_masq_frac / MASK_FOR_NON_SIGNIFICANT_DIGITS;
        match (
            (balance_masq_int == 0) && (balance_masq_frac_trunc == 0),
            balance_gwei >= 0,
        ) {
            (true, true) => "< 0.01".to_string(),
            (true, false) => "-0.01 < x < 0".to_string(),
            _ => {
                format!(
                    "{}{}.{:0>2}",
                    if balance_gwei < 0 { "-" } else { "" },
                    balance_masq_int.separate_with_commas(),
                    balance_masq_frac_trunc
                )
            }
        }
    }

    pub fn neaten_users_writing_if_possible(
        user_ranges: &UserOriginalTypingOfRanges,
    ) -> (String, String) {
        fn collect_captured_parts_of_a_number(captures: Captures) -> [Option<String>; 3] {
            let fetch_group = |idx: usize| -> Option<String> { single_capture(&captures, idx) };
            [fetch_group(1), fetch_group(2), fetch_group(3)]
        }
        fn assemble_string_segments_into_single_number(strings: [Option<String>; 3]) -> String {
            strings.into_iter().flatten().collect()
        }
        fn assemble_age_and_balance_string_ranges(
            mut numbers: VecDeque<String>,
        ) -> (String, String) {
            if numbers.get(3).expectv("fourth element").is_empty() {
                //meaning the 4th limit deliberately omitted by the user
                numbers[3] = "UNLIMITED".to_string()
            };
            let mut pop = || numbers.pop_front();
            (
                format!("{}-{}", pop().expectv("age min"), pop().expectv("age max")),
                format!(
                    "{}-{}",
                    pop().expectv("balance min"),
                    pop().expectv("balance max")
                ),
            )
        }

        //the 4th capture group is inactivated by ?:
        let simplifying_extractor =
            Regex::new(r#"^(-?)0*(\d+)(?:(\.\d*[1-9])0*$|\.0|$)"#).expect("wrong regex");
        let apply_care = |cached_user_input: &str| -> [Option<String>; 3] {
            simplifying_extractor
                .captures(cached_user_input)
                .map(collect_captured_parts_of_a_number)
                .unwrap_or_else(
                    || panic!("Broken code: value must have been present during a check but yet wrong: {}", cached_user_input)
                )
        };
        let ((time_min, time_max), (amount_min, amount_max)) = user_ranges;
        let vec_of_possibly_corrected_values = [
            apply_care(time_min),
            apply_care(time_max),
            apply_care(amount_min),
            if amount_max.is_empty() {
                Default::default()
            } else {
                apply_care(amount_max)
            },
        ]
        .into_iter()
        .map(assemble_string_segments_into_single_number)
        .collect::<VecDeque<String>>();
        assemble_age_and_balance_string_ranges(vec_of_possibly_corrected_values)
    }

    pub fn parse_masq_range_to_gwei<N>(range: &str) -> Result<(N, N, String, String), String>
    where
        N: FromStr<Err = ParseIntError> + TryFrom<i64> + TryFrom<u64> + CheckedMul + Display + Copy,
        i64: TryFrom<N>,
        u64: TryFrom<N>,
        <N as TryFrom<i64>>::Error: Debug,
        <i64 as TryFrom<N>>::Error: Debug,
    {
        let regex = Regex::new(r#"^((-?\d+\.?\d*)\s*-\s*(-?\d+\.?\d*))|(-?\d+\.?\d*)$"#)
            .expect("wrong regex");
        let (first, second_opt) = extract_individual_masq_values(range, regex)?;
        let first_numeral = process_optionally_fractional_number(&first)?;
        let second_numeral = if let Some(second) = second_opt.as_ref() {
            process_optionally_fractional_number(second)?
        } else {
            N::try_from(i64::MAX).expect("must fit in between limits")
        };
        Ok((
            first_numeral,
            second_numeral,
            first,
            second_opt.unwrap_or_default(), //None signifies unlimited bounds
        ))
    }

    pub fn parse_time_params(min_age: &str, max_age: &str) -> Result<(u64, u64), String> {
        Ok((
            parse_integer_within_limits(min_age)?,
            parse_integer_within_limits(max_age)?,
        ))
    }

    pub fn split_time_range(range: &str) -> (&str, &str) {
        let age_args: Vec<&str> = range.split('-').collect();
        (
            age_args.first().expectv("age min"),
            age_args.get(1).expectv("age max"),
        )
    }

    pub(super) fn parse_integer_within_limits<N>(str_gwei: &str) -> Result<N, String>
    where
        N: FromStr<Err = ParseIntError> + Copy + TryFrom<u64>,
        u64: TryFrom<N>,
    {
        fn error_msg<N: Separable>(
            gwei: &str,
            lower_expected_limit: N,
            higher_expected_limit: N,
        ) -> String {
            let numbers = [
                &gwei as &dyn Separable,
                &lower_expected_limit,
                &higher_expected_limit,
            ]
            .into_iter()
            .map(|value| value.separate_with_commas())
            .collect::<Vec<String>>();
            format!(
                "Supplied value of {} gwei overflows the tech limits. You probably want one between {} and {} MASQ", numbers[0], numbers[1], numbers[2]
            )
        }
        let handle_parsing_error = |str_gwei: &str, e: ParseIntError| -> String {
            let minus_sign_regex = Regex::new(r#"\s*-\s*\d+"#).expect("bad regex");
            match (e.kind(), minus_sign_regex.is_match(str_gwei)) {
                (IntErrorKind::NegOverflow | IntErrorKind::PosOverflow, _) => {
                    if type_name::<N>() == type_name::<u64>() {
                        error_msg(str_gwei, 0, MASQ_TOTAL_SUPPLY)
                    } else {
                        error_msg(
                            str_gwei,
                            -(MASQ_TOTAL_SUPPLY as i64),
                            MASQ_TOTAL_SUPPLY as i64,
                        )
                    }
                }
                (IntErrorKind::InvalidDigit, true) if type_name::<N>() == type_name::<u64>() => {
                    error_msg(str_gwei, 0, MASQ_TOTAL_SUPPLY)
                }
                _ => format!(
                    "Non numeric value '{}', it must be a valid integer",
                    str_gwei
                ),
            }
        };

        match str::parse::<N>(str_gwei) {
            Ok(int) => match u64::try_from(int) {
                Ok(int_as_u64) => {
                    if int_as_u64 <= i64::MAX as u64 {
                        Ok(int)
                    } else {
                        Err(error_msg(str_gwei, 0, MASQ_TOTAL_SUPPLY))
                    }
                }
                Err(_) => {
                    //This error can only signalize a negative number
                    //because we always expect N to be u64 or i64
                    Ok(int)
                }
            },
            Err(e) => Err(handle_parsing_error(str_gwei, e)),
        }
    }

    fn single_capture(captures: &Captures, idx: usize) -> Option<String> {
        captures.get(idx).map(|catch| catch.as_str().to_owned())
    }

    pub(super) fn extract_individual_masq_values(
        masq_in_range_str: &str,
        masq_values_in_range_regex: Regex,
    ) -> Result<(String, Option<String>), String> {
        fn handle_captures(captures: Captures) -> (Option<String>, Option<String>) {
            let fetch_group = |idx: usize| single_capture(&captures, idx);
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

        match masq_values_in_range_regex
            .captures(masq_in_range_str)
            .map(handle_captures)
        {
            Some((Some(first), Some(second))) => Ok((first, Some(second))),
            Some((Some(first), None)) => Ok((first, None)),
            _ => Err(format!(
                "Balance range '{}' in improper format",
                masq_in_range_str
            )),
        }
    }

    pub(super) fn process_optionally_fractional_number<N>(num: &str) -> Result<N, String>
    where
        N: FromStr<Err = ParseIntError> + TryFrom<i64> + TryFrom<u64> + CheckedMul + Display + Copy,
        i64: TryFrom<N>,
        u64: TryFrom<N>,
        <N as TryFrom<i64>>::Error: Debug,
        <i64 as TryFrom<N>>::Error: Debug,
    {
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
        let decimal_shift_to_wei = |parse_result: N, exponent: u32| {
            parse_result
                .checked_mul(&N::try_from(10_i64.pow(exponent)).expect("no fear"))
                .ok_or_else(|| {
                    format!(
                        "Amount bigger than the MASQ total supply: {}, total supply: {}",
                        num, MASQ_TOTAL_SUPPLY
                    )
                })
        };

        let dot_opt = num.chars().position(|char| char == '.');
        if let Some(dot_idx) = dot_opt {
            check_right_dot_usage(num, dot_idx)?;
            let full_range_of_digits = all_digits_with_dot_removed(num);
            let all_digits_with_dot_removed_parsed: N =
                parse_integer_within_limits(&full_range_of_digits)?;
            let decimal_digits_count = decimal_digits_count(num, dot_idx)?;
            decimal_shift_to_wei(
                all_digits_with_dot_removed_parsed,
                DIGITS_IN_BILLION - decimal_digits_count,
            )
        } else {
            let integer_parsed = parse_integer_within_limits::<N>(num)?;
            decimal_shift_to_wei(integer_parsed, DIGITS_IN_BILLION)
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
}

#[cfg(test)]
mod tests {
    use crate::commands::financials_command::parsing_and_value_dressing::restricted::{
        convert_masq_from_gwei_and_dress_well, extract_individual_masq_values,
        neaten_users_writing_if_possible, parse_integer_within_limits,
        process_optionally_fractional_number,
    };
    use crate::commands::financials_command::test_utils::transpose_inputs_to_nested_tuples;
    use masq_lib::constants::{MASQ_TOTAL_SUPPLY, WEIS_IN_GWEI};
    use regex::Regex;

    #[test]
    fn convert_masq_from_gwei_and_dress_well_handles_values_smaller_than_one_hundredth_of_masq_and_bigger_than_zero(
    ) {
        let gwei: i64 = 9999999;

        let result = convert_masq_from_gwei_and_dress_well(gwei);

        assert_eq!(result, "< 0.01")
    }

    #[test]
    fn convert_masq_from_gwei_and_dress_well_handles_values_bigger_than_minus_one_hundredth_of_masq_and_smaller_than_zero(
    ) {
        let gwei: i64 = -9999999;

        let result = convert_masq_from_gwei_and_dress_well(gwei);

        assert_eq!(result, "-0.01 < x < 0")
    }

    #[test]
    fn convert_masq_from_gwei_and_dress_well_handles_positive_number() {
        let gwei: i64 = 987654321987654;

        let result = convert_masq_from_gwei_and_dress_well(gwei);

        assert_eq!(result, "987,654.32")
    }

    #[test]
    fn convert_masq_from_gwei_and_dress_well_handles_negative_number() {
        let gwei: i64 = -1234567891234;

        let result = convert_masq_from_gwei_and_dress_well(gwei);

        assert_eq!(result, "-1,234.56")
    }

    #[test]
    fn neaten_users_writing_handles_leading_and_tailing_zeros() {
        let result = neaten_users_writing_if_possible(&transpose_inputs_to_nested_tuples([
            "00045656",
            "0354865.1500000",
            "000124856",
            "01561785.3300",
        ]));

        assert_eq!(
            result,
            (
                "45656-354865.15".to_string(),
                "124856-1561785.33".to_string()
            )
        )
    }

    #[test]
    fn neaten_users_writing_handles_plain_zero_after_the_dot() {
        let result = neaten_users_writing_if_possible(&transpose_inputs_to_nested_tuples([
            "45656.0",
            "354865.0",
            "124856.0",
            "1561785.0",
        ]));

        assert_eq!(
            result,
            ("45656-354865".to_string(), "124856-1561785".to_string())
        )
    }

    #[test]
    fn neaten_users_writing_returns_same_thing_if_no_change_needed() {
        let result = neaten_users_writing_if_possible(&transpose_inputs_to_nested_tuples([
            "456500", "35481533", "-500", "0.4545",
        ]));

        assert_eq!(
            result,
            ("456500-35481533".to_string(), "-500-0.4545".to_string())
        )
    }

    #[test]
    fn neaten_users_writing_returns_well_formatted_range_for_negative_values() {
        let result = neaten_users_writing_if_possible(&transpose_inputs_to_nested_tuples([
            "456500", "35481533", "-500", "-45",
        ]));

        assert_eq!(
            result,
            ("456500-35481533".to_string(), "-500--45".to_string())
        )
    }

    #[test]
    fn neaten_users_writing_treats_zero_followed_decimal_numbers_gently() {
        let result = neaten_users_writing_if_possible(&transpose_inputs_to_nested_tuples([
            "0.45545000",
            "000.333300",
            "000.00010000",
            "565.454500",
        ]));

        assert_eq!(
            result,
            ("0.45545-0.3333".to_string(), "0.0001-565.4545".to_string())
        )
    }

    #[test]
    #[should_panic(
        expected = "Broken code: value must have been present during a check but yet wrong: 0.4554booooga45"
    )]
    fn neaten_users_writing_complains_about_leaked_string_with_bad_syntax() {
        neaten_users_writing_if_possible(&transpose_inputs_to_nested_tuples([
            "0.4554booooga45",
            "333300",
            "0.0001",
            "565",
        ]));
    }

    #[test]
    fn parse_integer_overflow_indicates_too_big_number_supplied_for_i64() {
        let err_msg_i64: Result<i64, String> =
            parse_integer_within_limits(&(i64::MAX as u64 + 1).to_string());

        assert_eq!(err_msg_i64.unwrap_err(), "Supplied value of 9,223,372,036,854,775,808 gwei overflows the tech limits. You probably want one between -37,500,000 and 37,500,000 MASQ");

        let err_msg_i64: Result<i64, String> =
            parse_integer_within_limits(&(i64::MIN as i128 - 1).to_string());

        assert_eq!(err_msg_i64.unwrap_err(), "Supplied value of -9,223,372,036,854,775,809 gwei overflows the tech limits. You probably want one between -37,500,000 and 37,500,000 MASQ")
    }

    #[test]
    fn parse_integer_overflow_indicates_too_big_number_supplied_for_u64() {
        let err_msg_u64: Result<u64, String> =
            parse_integer_within_limits(&(i64::MAX as u64 + 1).to_string());

        assert_eq!(err_msg_u64.unwrap_err(), "Supplied value of 9,223,372,036,854,775,808 gwei overflows the tech limits. You probably want one between 0 and 37,500,000 MASQ");

        let err_msg_u64: Result<u64, String> = parse_integer_within_limits("-1");

        assert_eq!(err_msg_u64.unwrap_err(), "Supplied value of -1 gwei overflows the tech limits. You probably want one between 0 and 37,500,000 MASQ")
    }

    #[test]
    fn unparsable_u64_but_not_because_of_minus_sign() {
        let err_msg: Result<u64, String> = parse_integer_within_limits(".1");

        assert_eq!(
            err_msg.unwrap_err(),
            "Non numeric value '.1', it must be a valid integer"
        )
    }

    #[test]
    fn u64_detect_minus_sign_error_with_different_white_spaces_around() {
        ["- 5", "   -8", " - 1"].into_iter().for_each(|example|{
            let err_msg: Result<u64, String> =
                parse_integer_within_limits(example);
            assert_eq!(err_msg.unwrap_err(), format!("Supplied value of {} gwei overflows the tech limits. You probably want one between 0 and 37,500,000 MASQ", example))
        })
    }

    #[test]
    fn i64_interpretation_capabilities_are_good_enough_for_masq_total_supply_in_gwei() {
        let _: i64 = (MASQ_TOTAL_SUPPLY * WEIS_IN_GWEI as u64)
            .try_into()
            .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "entered unreachable code: the regex was designed not to allow 'None' for the second and 'Some(\"ghi\")' for the third capture group"
    )]
    fn extract_individual_masq_values_regex_is_wrong() {
        let regex = Regex::new("(abc)?(def)?(ghi)").unwrap();

        let _ = extract_individual_masq_values("ghi", regex);
    }

    #[test]
    fn process_optionally_fractional_number_dislikes_dot_as_the_last_char() {
        let result = process_optionally_fractional_number::<i64>("4556.");

        assert_eq!(
            result,
            Err("Ending dot at decimal number, like here '4556.', is unsupported".to_string())
        )
    }

    #[test]
    fn process_optionally_fractional_number_dislikes_more_than_one_dot() {
        let result = process_optionally_fractional_number::<i64>("45.056.000");

        assert_eq!(
            result,
            Err("Misused decimal number dot delimiter at '45.056.000'".to_string())
        )
    }
}
