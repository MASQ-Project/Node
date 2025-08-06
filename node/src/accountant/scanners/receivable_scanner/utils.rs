// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::receivable_dao::ReceivableAccount;
use crate::accountant::wei_to_gwei;
use std::time::{Duration, SystemTime};
use thousands::Separable;

pub fn balance_and_age(time: SystemTime, account: &ReceivableAccount) -> (String, Duration) {
    let balance = wei_to_gwei::<i64, i128>(account.balance_wei).separate_with_commas();
    let age = time
        .duration_since(account.last_received_timestamp)
        .unwrap_or_else(|_| Duration::new(0, 0));
    (balance, age)
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::receivable_dao::ReceivableAccount;
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::scanners::receivable_scanner::utils::balance_and_age;
    use crate::test_utils::make_wallet;
    use std::time::SystemTime;

    #[test]
    fn balance_and_age_is_calculated_as_expected() {
        let now = SystemTime::now();
        let offset = 1000;
        let receivable_account = ReceivableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: 10_000_000_000,
            last_received_timestamp: from_unix_timestamp(to_unix_timestamp(now) - offset),
        };

        let (balance, age) = balance_and_age(now, &receivable_account);

        assert_eq!(balance, "10");
        assert_eq!(age.as_secs(), offset as u64);
    }
}
