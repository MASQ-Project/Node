// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod setup_reporter_tests;

use crate::setup_reporter_tests::quad_tests_computed_default_body;
use proc_macro::TokenStream;
use syn;

#[proc_macro]
pub fn quad_tests_computed_default(input: TokenStream) -> TokenStream {
    let input = input.to_string();
    let args = input.split(',').collect::<Vec<&str>>();
    quad_tests_computed_default_body(args)
}
