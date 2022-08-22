use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::scanners::scanners::PayableScanner;
use crate::sub_lib::accountant::PaymentThresholds;
use itertools::Itertools;
use std::ops::Add;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

//for debugging only
pub(crate) fn investigate_debt_extremes(all_non_pending_payables: &[PayableAccount]) -> String {
    if all_non_pending_payables.is_empty() {
        "Payable scan found no debts".to_string()
    } else {
        struct PayableInfo {
            balance: i64,
            age: Duration,
        }
        let now = SystemTime::now();
        let init = (
            PayableInfo {
                balance: 0,
                age: Duration::ZERO,
            },
            PayableInfo {
                balance: 0,
                age: Duration::ZERO,
            },
        );
        let (biggest, oldest) = all_non_pending_payables.iter().fold(init, |sofar, p| {
            let (mut biggest, mut oldest) = sofar;
            let p_age = now
                .duration_since(p.last_paid_timestamp)
                .expect("Payable time is corrupt");
            {
                //look at a test if not understandable
                let check_age_parameter_if_the_first_is_the_same =
                    || -> bool { p.balance == biggest.balance && p_age > biggest.age };

                if p.balance > biggest.balance || check_age_parameter_if_the_first_is_the_same() {
                    biggest = PayableInfo {
                        balance: p.balance,
                        age: p_age,
                    }
                }

                let check_balance_parameter_if_the_first_is_the_same =
                    || -> bool { p_age == oldest.age && p.balance > oldest.balance };

                if p_age > oldest.age || check_balance_parameter_if_the_first_is_the_same() {
                    oldest = PayableInfo {
                        balance: p.balance,
                        age: p_age,
                    }
                }
            }
            (biggest, oldest)
        });
        format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                all_non_pending_payables.len(), biggest.balance, biggest.age.as_secs(),
                oldest.balance, oldest.age.as_secs())
    }
}

fn is_payable_qualified(
    payable_balance: i64,
    time_since_last_paid: u64,
    payment_thresholds: Rc<PaymentThresholds>,
) -> Option<u64> {
    // TODO: This calculation should be done in the database, if possible
    let maturity_time_limit = payment_thresholds.maturity_threshold_sec as u64;
    let permanent_allowed_debt = payment_thresholds.permanent_debt_allowed_gwei;

    if time_since_last_paid <= maturity_time_limit {
        return None;
    }

    if payable_balance <= permanent_allowed_debt {
        return None;
    }

    let payout_threshold = calculate_payout_threshold(time_since_last_paid, payment_thresholds);
    if payable_balance as f64 <= payout_threshold {
        return None;
    }

    Some(threshold as u64)
}

fn payable_time_diff(time: SystemTime, payable: &PayableAccount) -> u64 {
    time.duration_since(payable.last_paid_timestamp)
        .expect("Payable time is corrupt")
        .as_secs()
}

fn calculate_payout_threshold(x: u64, payment_thresholds: Rc<PaymentThresholds>) -> f64 {
    let m = -((payment_thresholds.debt_threshold_gwei as f64
        - payment_thresholds.permanent_debt_allowed_gwei as f64)
        / (payment_thresholds.threshold_interval_sec as f64
            - payment_thresholds.maturity_threshold_sec as f64));
    let b = payment_thresholds.debt_threshold_gwei as f64
        - m * payment_thresholds.maturity_threshold_sec as f64;
    m * x as f64 + b
}

// TODO: Test Me
pub(crate) fn qualified_payables_and_summary(
    non_pending_payables: Vec<PayableAccount>,
    payment_thresholds: Rc<PaymentThresholds>,
) -> (Vec<PayableAccount>, String) {
    let now = SystemTime::now();
    let qualified_summary = String::from("Paying qualified debts:\n");
    let qualified_payables = non_pending_payables
        .into_iter()
        .filter(|account| {
            let time_since_last_paid = payable_time_diff(now, payable);

            match is_payable_qualified(
                account.balance,
                time_since_last_paid,
                payment_thresholds.clone(),
            ) {
                Some(threshold) => {
                    qualified_summary.add(
                        "{} owed for {}sec exceeds threshold: {}; creditor: {}\n",
                        account.balance,
                        time_since_last_paid,
                        threshold,
                        account.wallet.clone(),
                    );
                    true
                }
                None => false,
            }
        })
        .collect::<Vec<PayableAccount>>();

    let summary = match qualified_payables.is_empty() {
        true => String::from("No Qualified Payables found."),
        false => qualified_summary,
    };

    (qualified_payables, summary)
}

#[cfg(test)]
mod tests {
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::tools::{
        is_payable_qualified, payable_debug_summary, payables_debug_summary,
    };
    use crate::bootstrapper::BootstrapperConfig;
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::make_populated_accountant_config_with_defaults;
    use std::rc::Rc;
    use std::time::SystemTime;

    #[test]
    fn payables_debug_summary_prints_pretty_summary() {
        let now = to_time_t(SystemTime::now());
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
        let payment_thresholds_rc = Rc::new(payment_thresholds.clone());
        let qualified_payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1000,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.threshold_interval_sec - 1234,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.threshold_interval_sec - 1,
                ),
                pending_payable_opt: None,
            },
        ];

        let result = payables_debug_summary(qualified_payables, payment_thresholds_rc);

        assert_eq!(result,
                   "Paying qualified debts:\n\
                   10001000 owed for 2593234sec exceeds threshold: 9512428; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   10000001 owed for 2592001sec exceeds threshold: 9999604; creditor: 0x0000000000000000000000000077616c6c657431"
        )
    }

    // TODO: Either make this test work or write an alternative test in the desired file
    // #[test]
    // fn threshold_calculation_depends_on_user_defined_payment_thresholds() {
    //     let safe_age_params_arc = Arc::new(Mutex::new(vec![]));
    //     let safe_balance_params_arc = Arc::new(Mutex::new(vec![]));
    //     let calculate_payable_threshold_params_arc = Arc::new(Mutex::new(vec![]));
    //     let balance = 5555;
    //     let how_far_in_past = Duration::from_secs(1111 + 1);
    //     let last_paid_timestamp = SystemTime::now().sub(how_far_in_past);
    //     let payable_account = PayableAccount {
    //         wallet: make_wallet("hi"),
    //         balance,
    //         last_paid_timestamp,
    //         pending_payable_opt: None,
    //     };
    //     let custom_payment_thresholds = PaymentThresholds {
    //         maturity_threshold_sec: 1111,
    //         payment_grace_period_sec: 2222,
    //         permanent_debt_allowed_gwei: 3333,
    //         debt_threshold_gwei: 4444,
    //         threshold_interval_sec: 5555,
    //         unban_below_gwei: 3333,
    //     };
    //     let mut bootstrapper_config = BootstrapperConfig::default();
    //     bootstrapper_config.accountant_config_opt = Some(AccountantConfig {
    //         scan_intervals: Default::default(),
    //         payment_thresholds: custom_payment_thresholds,
    //         suppress_initial_scans: false,
    //         when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
    //     });
    //     let payable_thresholds_tools = PayableThresholdToolsMock::default()
    //         .is_innocent_age_params(&safe_age_params_arc)
    //         .is_innocent_age_result(
    //             how_far_in_past.as_secs()
    //                 <= custom_payment_thresholds.maturity_threshold_sec as u64,
    //         )
    //         .is_innocent_balance_params(&safe_balance_params_arc)
    //         .is_innocent_balance_result(
    //             balance <= custom_payment_thresholds.permanent_debt_allowed_gwei,
    //         )
    //         .calculate_payout_threshold_params(&calculate_payable_threshold_params_arc)
    //         .calculate_payout_threshold_result(4567.0); //made up value
    //     let mut subject = AccountantBuilder::default()
    //         .bootstrapper_config(bootstrapper_config)
    //         .build();
    //     subject.scanners.payables.payable_thresholds_tools = Box::new(payable_thresholds_tools);
    //
    //     let result = subject.payable_exceeded_threshold(&payable_account);
    //
    //     assert_eq!(result, Some(4567));
    //     let mut safe_age_params = safe_age_params_arc.lock().unwrap();
    //     let safe_age_single_params = safe_age_params.remove(0);
    //     assert_eq!(*safe_age_params, vec![]);
    //     let (time_elapsed, curve_derived_time) = safe_age_single_params;
    //     assert!(
    //         (how_far_in_past.as_secs() - 3) < time_elapsed
    //             && time_elapsed < (how_far_in_past.as_secs() + 3)
    //     );
    //     assert_eq!(
    //         curve_derived_time,
    //         custom_payment_thresholds.maturity_threshold_sec as u64
    //     );
    //     let safe_balance_params = safe_balance_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *safe_balance_params,
    //         vec![(
    //             payable_account.balance,
    //             custom_payment_thresholds.permanent_debt_allowed_gwei
    //         )]
    //     );
    //     let mut calculate_payable_curves_params =
    //         calculate_payable_threshold_params_arc.lock().unwrap();
    //     let calculate_payable_curves_single_params = calculate_payable_curves_params.remove(0);
    //     assert_eq!(*calculate_payable_curves_params, vec![]);
    //     let (payment_thresholds, time_elapsed) = calculate_payable_curves_single_params;
    //     assert!(
    //         (how_far_in_past.as_secs() - 3) < time_elapsed
    //             && time_elapsed < (how_far_in_past.as_secs() + 3)
    //     );
    //     assert_eq!(payment_thresholds, custom_payment_thresholds)
    // }
}
