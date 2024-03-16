// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(test)]
use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::{
    render_complete_formulas_characteristics, COMPUTE_FORMULAS_CHARACTERISTICS,
};
use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use std::fmt::Debug;

const PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS: bool = true;

pub const DIAGNOSTICS_MIDDLE_COLUMN_WIDTH: usize = 58;

#[macro_export]
macro_rules! diagnostics {
    // Displays only a description of an event
    ($description: literal) => {
       diagnostics(
           None::<fn()->String>,
           $description,
           None::<fn()->String>
       )
    };
    // Displays a brief description and values from a collection
    ($description: literal, $debuggable_collection: expr) => {
        collection_diagnostics($description, $debuggable_collection)
    };
    // Displays a brief description and formatted literal with arguments
    ($description: literal, $($formatted_values: tt)*) => {
        diagnostics(
            None::<fn()->String>,
            $description,
            Some(|| format!($($formatted_values)*))
        )
    };
    // Displays an account by wallet address, brief description and formatted literal with arguments
    ($wallet_ref: expr, $description: expr,  $($formatted_values: tt)*) => {
        diagnostics(
            Some(||$wallet_ref.to_string()),
            $description,
            Some(|| format!($($formatted_values)*))
        )
    };
}

// Intended to be used through the overloaded macro diagnostics!() for better clearness
// and differentiation from the primary functionality
pub fn diagnostics<F1, F2>(
    subject_renderer_opt: Option<F1>,
    description: &str,
    value_renderer_opt: Option<F2>,
) where
    F1: FnOnce() -> String,
    F2: FnOnce() -> String,
{
    if PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS {
        let subject_column_length = if subject_renderer_opt.is_some() {
            WALLET_ADDRESS_LENGTH + 2
        } else {
            0
        };
        let subject = no_text_or_by_renderer(subject_renderer_opt);
        let values = no_text_or_by_renderer(value_renderer_opt);
        let description_length = DIAGNOSTICS_MIDDLE_COLUMN_WIDTH;
        eprintln!(
            "\n{:<subject_column_length$}{:<description_length$}  {}",
            subject, description, values,
        )
    }
}

fn no_text_or_by_renderer<F>(renderer_opt: Option<F>) -> String
where
    F: FnOnce() -> String,
{
    if let Some(renderer) = renderer_opt {
        renderer()
    } else {
        "".to_string()
    }
}

// Should be used via the macro diagnostics!() for better clearness and differentiation from
// the prime functionality
pub fn collection_diagnostics<DebuggableAccount: Debug>(
    label: &str,
    accounts: &[DebuggableAccount],
) {
    if PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS {
        eprintln!("{}", label);
        accounts
            .iter()
            .for_each(|account| eprintln!("{:?}", account));
    }
}

pub mod ordinary_diagnostic_functions {
    use crate::accountant::payment_adjuster::criteria_calculators::CriterionCalculator;
    use crate::accountant::payment_adjuster::diagnostics;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment,
    };
    use crate::accountant::QualifiedPayableAccount;
    use crate::sub_lib::wallet::Wallet;
    use thousands::Separable;

    pub fn possibly_outweighed_accounts_diagnostics(
        account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            &account_info.original_qualified_account.payable.wallet,
            "OUTWEIGHED ACCOUNT FOUND",
            "Original balance: {}, proposed balance: {}",
            account_info
                .original_qualified_account
                .payable
                .balance_wei
                .separate_with_commas(),
            account_info
                .proposed_adjusted_balance
                .separate_with_commas()
        );
    }

    pub fn account_nominated_for_disqualification_diagnostics(
        account_info: &UnconfirmedAdjustment,
        proposed_adjusted_balance: u128,
        disqualification_edge: u128,
    ) {
        diagnostics!(
            account_info
                .non_finalized_account
                .original_qualified_account
                .payable
                .wallet,
            "ACCOUNT NOMINATED FOR DISQUALIFICATION FOR INSIGNIFICANCE AFTER ADJUSTMENT",
            "Proposed: {}, disqualification limit: {}",
            proposed_adjusted_balance.separate_with_commas(),
            disqualification_edge.separate_with_commas()
        );
    }

    pub fn exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
        possible_extra_addition: u128,
    ) {
        diagnostics!(
            "EXHAUSTING CW ON PAYMENT",
            "For account {} from proposed {} to the possible maximum of {}",
            non_finalized_account_info
                .original_qualified_account
                .payable
                .wallet,
            non_finalized_account_info.proposed_adjusted_balance,
            non_finalized_account_info.proposed_adjusted_balance + possible_extra_addition
        );
    }

    pub fn not_exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            "FULLY EXHAUSTED CW, PASSING ACCOUNT OVER",
            "Account {} with original balance {} must be finalized with proposed {}",
            non_finalized_account_info
                .original_qualified_account
                .payable
                .wallet,
            non_finalized_account_info
                .original_qualified_account
                .payable
                .balance_wei,
            non_finalized_account_info.proposed_adjusted_balance
        );
    }

    pub fn proposed_adjusted_balance_diagnostics(
        account: &QualifiedPayableAccount,
        proposed_adjusted_balance: u128,
    ) {
        diagnostics!(
            &account.payable.wallet,
            "PROPOSED ADJUSTED BALANCE",
            "{}",
            proposed_adjusted_balance.separate_with_commas()
        );
    }

    pub fn try_finding_an_account_to_disqualify_diagnostics(
        disqualification_suspected_accounts: &[&UnconfirmedAdjustment],
        wallet: &Wallet,
    ) {
        diagnostics!(
            "PICKED DISQUALIFIED ACCOUNT",
            "From {:?} picked {}",
            disqualification_suspected_accounts,
            wallet
        );
    }

    pub fn calculated_criterion_and_weight_diagnostics(
        wallet_ref: &Wallet,
        calculator: &dyn CriterionCalculator,
        criterion: u128,
        added_in_the_sum: u128,
    ) {
        const FIRST_COLUMN_WIDTH: usize = 30;
        diagnostics!(
            wallet_ref,
            "PARTIAL CRITERION CALCULATED",
            "For {:<width$} {} and summed up to {}",
            calculator.calculator_type(),
            criterion.separate_with_commas(),
            added_in_the_sum.separate_with_commas(),
            width = FIRST_COLUMN_WIDTH
        );
    }
}

#[cfg(not(test))]
pub fn display_formulas_characteristics_according_to_compilation_mode() {
    // intentionally empty for production code
}

#[cfg(test)]
pub fn display_formulas_characteristics_according_to_compilation_mode() {
    if COMPUTE_FORMULAS_CHARACTERISTICS {
        render_complete_formulas_characteristics()
    }
}

#[cfg(test)]
pub mod formulas_progressive_characteristics {
    use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::AgeCriterionCalculator;
    use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::BalanceCriterionCalculator;
    use crate::accountant::payment_adjuster::criteria_calculators::{
        CalculatorInputHolder, CriterionCalculator,
    };
    use crate::accountant::payment_adjuster::test_utils::make_initialized_subject;
    use crate::test_utils::unshared_test_utils::standard_dir_for_test_input_data;
    use itertools::Itertools;
    use masq_lib::utils::convert_collection;
    use serde::de::Error;
    use serde::{Deserialize as NormalImplDeserialize, Deserializer};
    use serde_derive::Deserialize;
    use serde_json::Value;
    use std::fs::File;
    use std::io::Read;
    use std::iter::once;
    use std::path::{Path, PathBuf};
    use std::sync::Once;
    use std::time::{Duration, SystemTime};
    use thousands::Separable;

    // For the purposes of debugging and tuning the formulas up to work well together. It lets you
    // imagine the curve of a criterion in dependence to different supplied input values for
    // the give parameter
    pub const COMPUTE_FORMULAS_CHARACTERISTICS: bool = true;

    // You must preserve the 'static' keyword
    //
    // The singleton ensures that the characteristics are always displayed only once, no matter
    // how many tests requested
    static FORMULAS_CHARACTERISTICS_SINGLETON: Once = Once::new();

    pub fn render_complete_formulas_characteristics() {
        FORMULAS_CHARACTERISTICS_SINGLETON.call_once(|| {
            let comprehend_debug_summary = supply_real_formulas_to_render_characteristics();

            eprintln!("{}", comprehend_debug_summary)
        })
    }

    fn supply_real_formulas_to_render_characteristics() -> String {
        let payment_adjuster = make_initialized_subject(SystemTime::now(), None, None);

        let rendering_params: Vec<(&'static str, Box<dyn CriterionCalculator>, DiagnosticsAxisX)> = vec![
            (
                "BALANCE",
                Box::new(BalanceCriterionCalculator::new()),
                make_rendering_config_for_balance(),
            ),
            (
                "AGE",
                Box::new(AgeCriterionCalculator::new(&payment_adjuster)),
                make_rendering_config_for_age(),
            ),
        ];

        rendering_params
            .into_iter()
            .map(
                |(param_name, criterion_calculator, param_rendering_config)| {
                    let param_calculation_formula = criterion_calculator.formula();
                    compute_progressive_characteristics(
                        param_name,
                        param_calculation_formula,
                        param_rendering_config,
                    )
                },
            )
            .join("\n\n")
    }

    fn make_rendering_config_for_balance() -> DiagnosticsAxisX {
        let file_path = file_path("input_data_for_diagnostics_of_balance_criterion_formula.txt");
        let horizontal_axis_data_supply = read_diagnostics_inputs_from_file(&file_path);

        DiagnosticsAxisX {
            values: horizontal_axis_data_supply,
            convertor_to_expected_formula_input: Box::new(|balance_wei| {
                CalculatorInputHolder::DebtBalance(balance_wei)
            }),
        }
    }

    fn make_rendering_config_for_age() -> DiagnosticsAxisX {
        let now = SystemTime::now();
        let file_path = file_path("input_data_for_diagnostics_of_age_criterion_formula.txt");
        let horizontal_axis_data_supply = read_diagnostics_inputs_from_file(&file_path);
        let convertor_to_expected_formula_input_type =
            Box::new(move |secs_since_last_paid_payable: u128| {
                let native_time = now
                    .checked_sub(Duration::from_secs(secs_since_last_paid_payable as u64))
                    .expect("time travelling");
                CalculatorInputHolder::DebtAge {
                    last_paid_timestamp: native_time,
                }
            });

        DiagnosticsAxisX {
            values: horizontal_axis_data_supply,
            convertor_to_expected_formula_input: convertor_to_expected_formula_input_type,
        }
    }

    fn file_path(file_name: &str) -> PathBuf {
        standard_dir_for_test_input_data().join(file_name)
    }

    #[derive(Deserialize)]
    struct InputFromFile {
        literals: Vec<IntegerValueAllowingUnderscores>,
        decimal_exponents: Vec<u32>,
        marked_values: Vec<MarkedValueFromFile>,
    }

    #[derive(Deserialize)]
    struct MarkedValueFromFile {
        value: IntegerValueAllowingUnderscores,
        label: String,
    }

    struct MarkedValue {
        value: u128,
        label: String,
    }

    struct DeserializedInputValues {
        non_marked_values: Vec<u128>,
        marked_values: Vec<MarkedValue>,
    }

    struct DiagnosticsAxisX {
        values: DeserializedInputValues,
        convertor_to_expected_formula_input: Box<dyn Fn(u128) -> CalculatorInputHolder>,
    }

    struct IntegerValueAllowingUnderscores {
        numerical_value: u128,
    }

    impl IntegerValueAllowingUnderscores {
        fn new(value: u128) -> Self {
            Self {
                numerical_value: value,
            }
        }
    }

    impl<'de> NormalImplDeserialize<'de> for IntegerValueAllowingUnderscores {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let value: Value = NormalImplDeserialize::deserialize(deserializer)?;
            if let Value::String(str) = value {
                let underscore_less = str.chars().filter(|char| char != &'_').collect::<String>();
                let num: u128 = underscore_less.parse().unwrap();
                Ok(IntegerValueAllowingUnderscores::new(num))
            } else {
                Err(D::Error::custom(format!(
                    "Expected a string value but found: {:?}",
                    value
                )))
            }
        }
    }

    impl From<MarkedValueFromFile> for MarkedValue {
        fn from(marked_value_from_file: MarkedValueFromFile) -> Self {
            MarkedValue {
                value: marked_value_from_file.value.numerical_value,
                label: marked_value_from_file.label,
            }
        }
    }

    impl DiagnosticsAxisX {
        fn finalize_input_with_marked_values(&self) -> Vec<u128> {
            if self.values.marked_values.is_empty() {
                self.values.non_marked_values.clone()
            } else {
                let filtered_marked_values = self
                    .values
                    .marked_values
                    .iter()
                    .map(|marked_val| &marked_val.value);
                let standard_input = self.values.non_marked_values.iter();
                filtered_marked_values
                    .chain(standard_input)
                    .sorted()
                    .dedup()
                    .map(|num| *num)
                    .collect()
            }
        }
    }

    fn render_notation(coordinate_value: u128, marked_vals: &[MarkedValue]) -> String {
        match should_mark_be_used(coordinate_value, marked_vals) {
            Some(mark) => format!("{}  {}", coordinate_value.separate_with_commas(), mark),
            None => coordinate_value.separate_with_commas(),
        }
    }
    fn should_mark_be_used(coordinate_value: u128, marked_vals: &[MarkedValue]) -> Option<String> {
        if marked_vals.is_empty() {
            None
        } else {
            marked_vals
                .iter()
                .find(|marked_val| marked_val.value == coordinate_value)
                .map(|marked_val| marked_val.label.clone())
        }
    }

    fn compute_progressive_characteristics(
        param_name: &'static str,
        formula: &dyn Fn(CalculatorInputHolder) -> u128,
        rendering_config: DiagnosticsAxisX,
    ) -> String {
        let input_values = rendering_config.finalize_input_with_marked_values();
        let marked_input_values = rendering_config.values.marked_values.as_slice();
        let config_x_axis_type_formatter = rendering_config.convertor_to_expected_formula_input;

        let characteristics = input_values.into_iter().map(|single_coordinate| {
            let correctly_formatted_input = config_x_axis_type_formatter(single_coordinate);
            let input_with_commas = render_notation(single_coordinate, marked_input_values);
            let computed_value_with_commas =
                formula(correctly_formatted_input).separate_with_commas();
            format!(
                "x: {:<length$} y: {}",
                input_with_commas,
                computed_value_with_commas,
                length = 40
            )
        });

        let head = once(format!("CHARACTERISTICS OF {} FORMULA", param_name));
        head.into_iter().chain(characteristics).join("\n")
    }

    fn read_diagnostics_inputs_from_file(path: &Path) -> DeserializedInputValues {
        let mut file = File::open(path).unwrap_or_else(|e| {
            panic!("Inputs badly prepared at path: {:?}, error: {:?}", path, e)
        });
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        let plain_json: String = buffer
            .lines()
            .filter(|line| !line.is_empty() && !line_is_comment(line))
            .collect();
        let processed_json_input = serde_json::from_str::<InputFromFile>(&plain_json)
            .unwrap_or_else(|e| {
                panic!(
                    "Error {:?} for file path: {:?}. Read string: {}",
                    e, path, plain_json
                )
            });

        let nums_declared_as_literals = processed_json_input
            .literals
            .into_iter()
            .map(|wrapper| wrapper.numerical_value)
            .collect();

        let marked_values = convert_collection(processed_json_input.marked_values);

        DeserializedInputValues {
            non_marked_values: serialize_values_on_x_axis_from_vecs(
                nums_declared_as_literals,
                processed_json_input.decimal_exponents,
            ),
            marked_values,
        }
    }

    fn line_is_comment(line: &str) -> bool {
        let char_collection = line
            .chars()
            .skip_while(|char| char.is_ascii_whitespace())
            .take(1)
            .collect::<Vec<char>>();
        let first_meaningful_char_opt = char_collection.first();
        if first_meaningful_char_opt.is_none() {
            panic!("Something went wrong. Empty lines should have been already tested")
        }
        first_meaningful_char_opt.unwrap() == &'#'
    }

    pub fn serialize_values_on_x_axis_from_vecs(
        nums_declared_as_literals: Vec<u128>,
        nums_declared_as_decimal_exponents: Vec<u32>,
    ) -> Vec<u128> {
        let exponent_based_numbers = nums_declared_as_decimal_exponents
            .into_iter()
            .map(|exponent| 10_u128.pow(exponent));
        nums_declared_as_literals
            .into_iter()
            .chain(exponent_based_numbers)
            .sorted()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::COMPUTE_FORMULAS_CHARACTERISTICS;
    use crate::accountant::payment_adjuster::diagnostics::PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS;

    #[test]
    fn constants_are_correct() {
        assert_eq!(PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS, false);
        assert_eq!(COMPUTE_FORMULAS_CHARACTERISTICS, false)
    }
}
