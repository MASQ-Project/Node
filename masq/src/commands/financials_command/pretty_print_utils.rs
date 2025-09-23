// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::commands::financials_command) mod restricted {
    use crate::commands::financials_command::data_structures::restricted::{
        HeadingsHolder, ProcessAccountsMetadata, UserOriginalTypingOfRanges,
    };
    use crate::commands::financials_command::parsing_and_value_dressing::restricted::{
        convert_masq_from_gwei_and_dress_well, neaten_users_writing_if_possible,
    };
    use crate::commands::financials_command::FinancialsCommand;
    use masq_lib::constants::WALLET_ADDRESS_LENGTH;
    use masq_lib::messages::{UiPayableAccount, UiReceivableAccount};
    use masq_lib::short_writeln;
    use masq_lib::utils::to_string;
    use std::fmt::{Debug, Display, Formatter};
    use std::io::Write;
    use thousands::Separable;

    pub trait StringValuesFormattableAccount {
        fn convert_to_strings(&self, ordinal_num: usize, is_gwei: bool) -> Vec<String>;
    }

    impl StringValuesFormattableAccount for UiPayableAccount {
        fn convert_to_strings(&self, ordinal_num: usize, is_gwei: bool) -> Vec<String> {
            vec![
                ordinal_num.to_string(),
                self.wallet.to_string(),
                self.age_s.separate_with_commas(),
                process_gwei_into_requested_format(self.balance_gwei, is_gwei),
                match &self.current_tx_info_opt {
                    Some(current_tx_info) => match &current_tx_info.pending_tx_hash_opt {
                        Some(hash) => {
                            if current_tx_info.failures == 0 {
                                hash.clone()
                            } else {
                                format!(
                                    "{} ({})",
                                    hash,
                                    AttemptsConjugator::new(current_tx_info.failures)
                                )
                            }
                        }
                        None => {
                            format!(
                                "Processing... {}",
                                AttemptsConjugator::new(current_tx_info.failures)
                            )
                        }
                    },
                    None => "None".to_string(),
                },
            ]
        }
    }

    impl StringValuesFormattableAccount for UiReceivableAccount {
        fn convert_to_strings(&self, ordinal_num: usize, is_gwei: bool) -> Vec<String> {
            vec![
                ordinal_num.to_string(),
                self.wallet.to_string(),
                self.age_s.separate_with_commas(),
                process_gwei_into_requested_format(self.balance_gwei, is_gwei),
            ]
        }
    }

    pub(super) struct AttemptsConjugator {
        failures: usize,
    }

    impl AttemptsConjugator {
        pub fn new(failures: usize) -> Self {
            Self { failures }
        }
    }

    impl Display for AttemptsConjugator {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            if self.failures == 1 {
                write!(f, "1 failed attempt")
            } else {
                write!(f, "{} failed attempts", self.failures)
            }
        }
    }

    pub fn financial_status_totals_title(stdout: &mut dyn Write, is_gwei: bool) {
        short_writeln!(
            stdout,
            "\nFinancial status totals in {}\n",
            &gwei_or_masq_balance(is_gwei)[9..13]
        );
    }

    pub fn main_title_for_tops_opt(fin_com: &FinancialsCommand, stdout: &mut dyn Write) {
        if let Some(tr_config) = fin_com.top_records_opt.as_ref() {
            short_writeln!(stdout, "Up to {} top accounts\n", tr_config.count)
        }
    }

    pub fn subtitle_for_tops(stdout: &mut dyn Write, account_type: &str) {
        fn capitalize(name: &str) -> String {
            let mut letter_iterator = name.chars();
            let first = letter_iterator
                .next()
                .expect("empty string instead of name");
            first.to_uppercase().chain(letter_iterator).collect()
        }
        short_writeln!(stdout, "{}\n", capitalize(account_type))
    }

    pub fn title_for_custom_query(
        stdout: &mut dyn Write,
        table_type: &str,
        user_written_ranges: &UserOriginalTypingOfRanges,
    ) {
        let (age_range, balance_range) = neaten_users_writing_if_possible(user_written_ranges);
        short_writeln!(
            stdout,
            "Specific {} query: {} sec {} MASQ\n",
            table_type,
            age_range,
            balance_range
        )
    }

    pub fn render_accounts_generic<A: StringValuesFormattableAccount>(
        stdout: &mut dyn Write,
        accounts: Vec<A>,
        headings: &HeadingsHolder,
    ) {
        let preformatted_subset = &accounts
            .iter()
            .enumerate()
            .map(|(idx, account)| account.convert_to_strings(idx + 1, headings.is_gwei))
            .collect::<Vec<_>>();
        let optimal_widths = width_precise_calculation(headings, preformatted_subset);
        let headings_and_widths = &zip_them(headings.words.as_slice(), &optimal_widths);
        write_column_formatted(stdout, headings_and_widths);
        preformatted_subset.iter().for_each(|account| {
            let zipped_inputs = zip_them(account, &optimal_widths);
            write_column_formatted(stdout, &zipped_inputs);
        });
    }

    pub fn process_gwei_into_requested_format<N>(gwei: N, should_stay_gwei: bool) -> String
    where
        N: From<u32> + Separable + Display,
        i64: TryFrom<N>,
        <i64 as TryFrom<N>>::Error: Debug,
    {
        if should_stay_gwei {
            gwei.separate_with_commas()
        } else {
            let gwei_as_i64 = i64::try_from(gwei)
                .expect("Clap validation failed: value bigger than i64::MAX is forbidden");
            convert_masq_from_gwei_and_dress_well(gwei_as_i64)
        }
    }

    pub fn triple_or_single_blank_line(stdout: &mut dyn Write, leading_dump: bool) {
        if leading_dump {
            short_writeln!(stdout)
        } else {
            short_writeln!(stdout, "\n\n")
        }
    }

    pub fn no_records_found(stdout: &mut dyn Write, headings: &[String]) {
        let mut headings_widths = widths_of_str_values(headings);
        headings_widths[1] = WALLET_ADDRESS_LENGTH;
        write_column_formatted(stdout, &zip_them(headings, &headings_widths));
        short_writeln!(stdout, "\nNo records found",)
    }

    pub fn prepare_metadata(is_gwei: bool) -> (ProcessAccountsMetadata, ProcessAccountsMetadata) {
        let (payable_headings, receivable_headings) = prepare_headings_of_records(is_gwei);
        (
            ProcessAccountsMetadata {
                table_type: "payable",
                headings: payable_headings,
            },
            ProcessAccountsMetadata {
                table_type: "receivable",
                headings: receivable_headings,
            },
        )
    }

    fn gwei_or_masq_balance(is_gwei: bool) -> String {
        format!("Balance {}", gwei_or_masq_units(is_gwei))
    }

    fn gwei_or_masq_units(is_gwei: bool) -> &'static str {
        if is_gwei {
            "[gwei]"
        } else {
            "[MASQ]"
        }
    }

    fn prepare_headings_of_records(is_gwei: bool) -> (HeadingsHolder, HeadingsHolder) {
        fn to_owned_strings(words: Vec<&str>) -> Vec<String> {
            words.iter().map(to_string).collect()
        }
        let balance = gwei_or_masq_balance(is_gwei);
        (
            HeadingsHolder {
                words: to_owned_strings(vec!["#", "Wallet", "Age [s]", &balance, "Pending tx"]),
                is_gwei,
            },
            HeadingsHolder {
                words: to_owned_strings(vec!["#", "Wallet", "Age [s]", &balance]),
                is_gwei,
            },
        )
    }

    fn width_precise_calculation(
        headings: &HeadingsHolder,
        values_of_accounts: &[Vec<String>],
    ) -> Vec<usize> {
        let headings_widths = widths_of_str_values(headings.words.as_slice());
        let values_widths = figure_out_max_widths(values_of_accounts);
        yield_bigger_values_from_vecs(headings_widths, &values_widths)
    }

    fn widths_of_str_values<T: AsRef<str>>(headings: &[T]) -> Vec<usize> {
        headings
            .iter()
            .map(|phrase| phrase.as_ref().len())
            .collect()
    }

    fn zip_them<'a>(
        words: &'a [String],
        optimal_widths: &'a [usize],
    ) -> Vec<(&'a String, &'a usize)> {
        words.iter().zip(optimal_widths.iter()).collect()
    }

    fn write_column_formatted(
        stdout: &mut dyn Write,
        account_segments_values_as_strings_and_widths: &[(&String, &usize)],
    ) {
        let column_count = account_segments_values_as_strings_and_widths.len();
        account_segments_values_as_strings_and_widths
            .iter()
            .enumerate()
            .for_each(|(idx, (value, optimal_width))| {
                write!(
                    stdout,
                    "{:<width$}{:gap$}",
                    value,
                    "",
                    width = optimal_width,
                    gap = if idx + 1 == column_count { 0 } else { 3 }
                )
                .expect("write failed")
            });
        short_writeln!(stdout, "")
    }

    pub(super) fn figure_out_max_widths(values_of_accounts: &[Vec<String>]) -> Vec<usize> {
        //two-dimensional set of strings; measuring their lengths and saving the largest value for each column
        //the first value (ordinal number) and the second (wallet) are processed specifically, in shortcut
        let init = vec![0_usize; values_of_accounts[0].len() - 2];
        let widths_except_ordinal_num = values_of_accounts.iter().fold(init, |acc, record| {
            yield_bigger_values_from_vecs(acc, &widths_of_str_values(record)[2..])
        });
        let mut result = vec![
            (values_of_accounts.len() as f64).log10() as usize + 1,
            WALLET_ADDRESS_LENGTH,
        ];
        result.extend(widths_except_ordinal_num);
        result
    }

    fn yield_bigger_values_from_vecs(first: Vec<usize>, second: &[usize]) -> Vec<usize> {
        (0..first.len()).fold(vec![], |mut acc, idx| {
            acc.push(first[idx].max(second[idx]));
            acc
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::financials_command::pretty_print_utils::restricted::{
        figure_out_max_widths, AttemptsConjugator, StringValuesFormattableAccount,
    };

    #[derive(Clone)]
    struct TestAccount {
        a: &'static str,
        b: &'static str,
        c: &'static str,
    }

    impl StringValuesFormattableAccount for TestAccount {
        fn convert_to_strings(&self, ordinal_num: usize, _gwei: bool) -> Vec<String> {
            vec![
                ordinal_num.to_string(),
                self.a.to_string(),
                self.b.to_string(),
                self.c.to_string(),
            ]
        }
    }

    #[test]
    fn figure_out_max_widths_works() {
        let mut vec_of_accounts = vec![
            TestAccount {
                a: "all",
                b: "howdy",
                c: "15489",
            },
            TestAccount {
                a: "whoooooo",
                b: "the",
                c: "meow",
            },
            TestAccount {
                a: "ki",
                b: "",
                c: "baabaalooo",
            },
        ];
        //filling used to reach an ordinal number with more than just one digit, here three digits
        vec_of_accounts.append(&mut vec![
            TestAccount {
                a: "",
                b: "",
                c: ""
            };
            100
        ]);
        let preformatted_subset = &vec_of_accounts
            .iter()
            .enumerate()
            .map(|(idx, account)| account.convert_to_strings(idx, false))
            .collect::<Vec<_>>();

        let result = figure_out_max_widths(&preformatted_subset);

        //the first number means number of digits within the biggest ordinal number
        //the second number is always 42 as the length of wallet address
        assert_eq!(result, vec![3, 42, 5, 10])
    }

    #[test]
    fn failures_conjugator_works_for_singular_failure() {
        let subject = AttemptsConjugator::new(1);
        assert_eq!(subject.to_string(), "1 failed attempt")
    }

    #[test]
    fn failures_conjugator_works_for_plural_failure() {
        let failures = vec![2, 5, 10];

        failures.iter().for_each(|failure| {
            let subject = AttemptsConjugator::new(*failure);
            assert_eq!(subject.to_string(), format!("{} failed attempts", failure))
        })
    }
}
