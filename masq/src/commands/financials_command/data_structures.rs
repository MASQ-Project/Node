// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::commands::financials_command) mod visibility_restricted {
    use masq_lib::messages::{CustomQueries, RangeQuery};

    #[derive(Debug, PartialEq, Eq)]
    pub struct CustomQueryInput {
        pub query: CustomQueries,
        pub users_payable_format_opt: Option<UserOriginalTypingOfRanges>,
        pub users_receivable_format_opt: Option<UserOriginalTypingOfRanges>,
    }

    pub type UserOriginalTypingOfRanges = ((String, String), (String, String));

    pub struct RangeQueryInput<T> {
        pub num_values: RangeQuery<T>,
        pub captured_literal_input: UserOriginalTypingOfRanges,
    }

    pub struct ProcessAccountsMetadata {
        pub table_type: &'static str,
        pub headings: HeadingsHolder,
    }

    pub struct HeadingsHolder {
        pub words: Vec<String>,
        pub is_gwei: bool,
    }
}
