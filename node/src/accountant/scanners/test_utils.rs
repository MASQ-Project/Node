// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::QualifiedPayableAccount;
use masq_lib::type_obfuscation::Obfuscated;

pub fn protect_qualified_payables_in_test(payables: Vec<QualifiedPayableAccount>) -> Obfuscated {
    Obfuscated::obfuscate_vector(payables)
}
