// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::commands::financials_command) mod restricted {
    use masq_lib::constants::{WEIS_IN_GWEI};
    use masq_lib::utils::ExpectValue;
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

    pub fn parse_time_params(min_age: &str, max_age: &str) -> Result<(u64, u64), String> {
        fn parse_u64_friendly(age: &str) -> Result<u64, String> {
            match str::parse::<u64> (age) {
                Ok(value) => Ok(value),
                Err(e) => todo! ("I need the right error message here"),//Err("blah".to_string()),
            }
        }
        Ok((
            parse_u64_friendly(min_age)?,
            parse_u64_friendly(max_age)?,
        ))
    }

    pub fn split_time_range(range: &str) -> (&str, &str) {
        let age_args: Vec<&str> = range.split('-').collect();
        (
            age_args.first().expectv("age min"),
            age_args.get(1).expectv("age max"),
        )
    }
    //
    // pub(super) fn parse_integer_within_limits<N: FromStr<Err = ParseIntError>>(str_gwei: &str) -> Result<N, String>
    // // where
    // //     N: FromStr<Err = ParseIntError> + Copy + TryFrom<u64>,
    // //     u64: TryFrom<N>,
    // {
    //     fn error_msg<N: Separable>(
    //         gwei: &str,
    //         lower_expected_limit: N,
    //         higher_expected_limit: N,
    //     ) -> String {
    //         let numbers = [
    //             &gwei as &dyn Separable,
    //             &lower_expected_limit,
    //             &higher_expected_limit,
    //         ]
    //         .into_iter()
    //         .map(|value| value.separate_with_commas())
    //         .collect::<Vec<String>>();
    //         format!(
    //             "Supplied value of {} gwei overflows the tech limits. You probably want one between {} and {} MASQ", numbers[0], numbers[1], numbers[2]
    //         )
    //     }
    //     let handle_parsing_error = |str_gwei: &str, e: ParseIntError| -> String {
    //         let minus_sign_regex = Regex::new(r#"\s*-\s*\d+"#).expect("bad regex");
    //         match (e.kind(), minus_sign_regex.is_match(str_gwei)) {
    //             (IntErrorKind::NegOverflow | IntErrorKind::PosOverflow, _) => {
    //                 if type_name::<N>() == type_name::<u64>() {
    //                     error_msg(str_gwei, 0, MASQ_TOTAL_SUPPLY)
    //                 } else {
    //                     error_msg(
    //                         str_gwei,
    //                         -(MASQ_TOTAL_SUPPLY as i64),
    //                         MASQ_TOTAL_SUPPLY as i64,
    //                     )
    //                 }
    //             }
    //             (IntErrorKind::InvalidDigit, true) if type_name::<N>() == type_name::<u64>() => {
    //                 error_msg(str_gwei, 0, MASQ_TOTAL_SUPPLY)
    //             }
    //             _ => format!(
    //                 "Non numeric value '{}', it must be a valid integer",
    //                 str_gwei
    //             ),
    //         }
    //     };
    //
    //     match str::parse::<N>(str_gwei) {
    //         // Ok(int) => match u64::try_from(int) {
    //         //     Ok(int_as_u64) => {
    //         //         if int_as_u64 <= i64::MAX as u64 {
    //         //             Ok(int)
    //         //         } else {
    //         //             Err(error_msg(str_gwei, 0, MASQ_TOTAL_SUPPLY))
    //         //         }
    //         //     }
    //         //     Err(_) => {
    //         //         //This error can only signalize a negative number
    //         //         //because we always expect N to be u64 or i64
    //         //         Ok(int)
    //         //     }
    //         // },
    //         Ok(int) => Ok(int),
    //         Err(e) => Err(handle_parsing_error(str_gwei, e)),
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use crate::commands::financials_command::parsing_and_value_dressing::restricted::{
        convert_masq_from_gwei_and_dress_well,
    };
    use masq_lib::constants::{MASQ_TOTAL_SUPPLY, WEIS_IN_GWEI};

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

    // #[test]
    // fn parse_integer_overflow_indicates_too_big_number_supplied_for_i64() {
    //     let err_msg_i64: Result<i64, String> =
    //         parse_integer_within_limits(&(i64::MAX as u64 + 1).to_string());
    //
    //     assert_eq!(err_msg_i64.unwrap_err(), "Supplied value of 9,223,372,036,854,775,808 gwei overflows the tech limits. You probably want one between -37,500,000 and 37,500,000 MASQ");
    //
    //     let err_msg_i64: Result<i64, String> =
    //         parse_integer_within_limits(&(i64::MIN as i128 - 1).to_string());
    //
    //     assert_eq!(err_msg_i64.unwrap_err(), "Supplied value of -9,223,372,036,854,775,809 gwei overflows the tech limits. You probably want one between -37,500,000 and 37,500,000 MASQ")
    // }

    // #[test]
    // fn parse_integer_overflow_indicates_too_big_number_supplied_for_u64() {
    //     let err_msg_u64: Result<u64, String> =
    //         parse_integer_within_limits(&(i64::MAX as u64 + 1).to_string());
    //
    //     assert_eq!(err_msg_u64.unwrap_err(), "Supplied value of 9,223,372,036,854,775,808 gwei overflows the tech limits. You probably want one between 0 and 37,500,000 MASQ");
    //
    //     let err_msg_u64: Result<u64, String> = parse_integer_within_limits("-1");
    //
    //     assert_eq!(err_msg_u64.unwrap_err(), "Supplied value of -1 gwei overflows the tech limits. You probably want one between 0 and 37,500,000 MASQ")
    // }

    // #[test]
    // fn unparsable_u64_but_not_because_of_minus_sign() {
    //     let err_msg: Result<u64, String> = parse_integer_within_limits(".1");
    //
    //     assert_eq!(
    //         err_msg.unwrap_err(),
    //         "Non numeric value '.1', it must be a valid integer"
    //     )
    // }

    // #[test]
    // fn u64_detect_minus_sign_error_with_different_white_spaces_around() {
    //     ["- 5", "   -8", " - 1"].into_iter().for_each(|example|{
    //         let err_msg: Result<u64, String> =
    //             parse_integer_within_limits(example);
    //         assert_eq!(err_msg.unwrap_err(), format!("Supplied value of {} gwei overflows the tech limits. You probably want one between 0 and 37,500,000 MASQ", example))
    //     })
    // }

    #[test]
    fn i64_interpretation_capabilities_are_good_enough_for_masq_total_supply_in_gwei() {
        let _: i64 = (MASQ_TOTAL_SUPPLY * WEIS_IN_GWEI as u64)
            .try_into()
            .unwrap();
    }
}
