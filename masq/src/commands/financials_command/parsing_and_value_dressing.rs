// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::commands::financials_command) mod restricted {
    use masq_lib::constants::WEIS_IN_GWEI;
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
}

#[cfg(test)]
mod tests {
    use crate::commands::financials_command::parsing_and_value_dressing::restricted::convert_masq_from_gwei_and_dress_well;
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

    #[test]
    fn i64_interpretation_capabilities_are_good_enough_for_masq_total_supply_in_gwei() {
        let _: i64 = (MASQ_TOTAL_SUPPLY * WEIS_IN_GWEI as u64)
            .try_into()
            .unwrap();
    }
}
