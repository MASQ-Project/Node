// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::inner::PaymentAdjusterInnerReal;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use crate::test_utils::make_wallet;
use itertools::Either;
use lazy_static::lazy_static;
use masq_lib::constants::MASQ_TOTAL_SUPPLY;
use masq_lib::logger::Logger;
use std::time::{Duration, SystemTime};

lazy_static! {
    pub static ref MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR: u128 =
        MASQ_TOTAL_SUPPLY as u128 * 10_u128.pow(18);
    pub static ref ONE_MONTH_LONG_DEBT_SEC: u64 = 30 * 24 * 60 * 60;
}

pub fn make_initialized_subject(
    now: SystemTime,
    cw_masq_balance_opt: Option<u128>,
    logger_opt: Option<Logger>,
) -> PaymentAdjusterReal {
    PaymentAdjusterReal {
        inner: Box::new(PaymentAdjusterInnerReal::new(
            now,
            None,
            cw_masq_balance_opt.unwrap_or(0),
        )),
        logger: logger_opt.unwrap_or(Logger::new("test")),
    }
}

pub fn make_extreme_accounts(
    months_of_debt_vs_balance_setup: Either<(Vec<usize>, u128), Vec<(usize, u128)>>,
    now: SystemTime,
) -> Vec<PayableAccount> {
    let accounts_seed: Vec<(usize, u128)> = match months_of_debt_vs_balance_setup {
        Either::Left((vec, constant_balance)) => vec
            .into_iter()
            .map(|months| (months, constant_balance))
            .collect(),
        Either::Right(vec_of_pairs) => vec_of_pairs,
    };
    accounts_seed
        .into_iter()
        .enumerate()
        .map(|(idx, (months_count, balance_wei))| PayableAccount {
            wallet: make_wallet(&format!("blah{}", idx)),
            balance_wei,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    months_count as u64 * (*ONE_MONTH_LONG_DEBT_SEC),
                ))
                .unwrap(),
            pending_payable_opt: None,
        })
        .collect()
}
