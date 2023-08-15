// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use serde_derive::{Deserialize, Serialize};
use std::io::Read;
use std::mem::transmute;

pub struct ProtectedPayables(Vec<u8>);

impl From<Vec<PayableAccount>> for ProtectedPayables {
    fn from(payables: Vec<PayableAccount>) -> Self {
        let bytes = unsafe { transmute::<Vec<PayableAccount>, Vec<u8>>(payables) };
        ProtectedPayables(bytes)
    }
}

impl From<ProtectedPayables> for Vec<PayableAccount> {
    fn from(protected: ProtectedPayables) -> Self {
        unsafe { transmute::<Vec<u8>, Vec<PayableAccount>>(protected.0) }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::protected_payables::ProtectedPayables;
    use crate::accountant::test_utils::{make_payable_account, make_payables};

    #[test]
    fn protected_payables_can_be_cast_from_and_back_to_vec_of_payable_accounts() {
        let initial_unprotected = vec![make_payable_account(123), make_payable_account(456)];

        let protected = ProtectedPayables::from(initial_unprotected.clone());
        let again_unprotected: Vec<PayableAccount> = protected.into();

        assert_eq!(initial_unprotected, again_unprotected)
    }
}
