// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub trait CommonMethods<Other> {
    fn partial_eq(&self, other: &Other) -> bool;
    fn clone_boxed(&self) -> Other;
    as_any_ref_in_trait!();
}
