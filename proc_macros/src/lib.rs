// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod setup_reporter_tests;

use crate::setup_reporter_tests::triple_test_computed_default_body;
use proc_macro::TokenStream;

#[proc_macro]
pub fn triple_test_computed_default(input: TokenStream) -> TokenStream {
    let input = input.to_string();
    let args = input.split(',').collect::<Vec<&str>>();
    triple_test_computed_default_body(args)
}

//cargo rustc --profile=check -- -Zunpretty=expanded
