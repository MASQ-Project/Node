// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

extern crate proc_macro;

use heck::CamelCase;
use proc_macro::TokenStream;
use std::fmt::Display;

pub fn triple_test_computed_default_body(args: Vec<&str>) -> TokenStream {
    let name = args[0];
    let full_default = args[1];
    let bootstrapper_config_destination = args[2];
    let num_cast_type = args[3];
    let alternative_data_type = args[4];
    let mut fundamental_default = args[1]
        .chars()
        .take_while(|char| char != &'.')
        .collect::<String>();
    if fundamental_default.chars().last().unwrap() == '.' {
        fundamental_default = fundamental_default[..fundamental_default.len() - 1].to_string()
    };
    let name_camel_case = name.to_camel_case();
    let length_differ = full_default.len() != fundamental_default.len();
    let default_location = if length_differ {
        format!("{}.{}", fundamental_default, name)
    } else {
        fundamental_default.clone()
    };
    let test_value_1 = configure_test_specific_section(name, length_differ, 0);
    let test_value_2 = configure_test_specific_section(name, length_differ, 555);
    let test_value_3 = configure_test_specific_section(name, length_differ, 1000);
    let non_primitive_conv = configure_prospective_non_primitive_conversion(alternative_data_type);
    format!(
        "
    #[test]
    fn {nm}_computed_default_all_defaulted(){{
        let subject = {nmcc}{{}};
        let mut bootstrapper_config = BootstrapperConfig::new();
        let mut fundamental_default = {fd}.clone();
        {cs1}
        bootstrapper_config.{bcd} = Some({conv});

        let result = subject.computed_default(
            &bootstrapper_config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(
            result,
            Some((
                {dfl}.to_string(),
                Default
            ))
        )
    }}

    #[test]
    fn {nm}_computed_default_bootstrapper_config_absent_persistent_value_unequal_to_default() {{
        let subject = {nmcc}{{}};
        let persistent_config = PersistentConfigurationMock::default()
            .{nm}_result(
                Ok(
                   ({dfl} + 555) as {nct})
            );
        let mut bootstrapper_config = BootstrapperConfig::new();
        let mut fundamental_default = {fd}.clone();
        {cs2}
        bootstrapper_config.{bcd} = Some({conv});

        let result = subject.computed_default(
            &bootstrapper_config,
            &persistent_config,
            &None,
        );

        assert_eq!(
            result,
            Some((
                ({dfl} + 555).to_string(),
                Configured
            ))
        )
    }}

    #[test]
    fn {nm}_computed_default_bootstrapper_config_different_from_persistent_config_value() {{
        let subject = {nmcc}{{}};
        let persistent_config = PersistentConfigurationMock::default()
            .{nm}_result(Ok(({dfl} + 555) as {nct}));
        let mut bootstrapper_config = BootstrapperConfig::new();
        let mut fundamental_default = {fd}.clone();
        {cs3}
        bootstrapper_config.{bcd} = Some({conv});
        let result = subject.computed_default(
            &bootstrapper_config,
            &persistent_config,
            &None,
        );
        assert_eq!(
            result,
            None
        )
    }}
    ",
        nm = name,
        nmcc = name_camel_case,
        dfl = default_location,
        fd = fundamental_default,
        bcd = bootstrapper_config_destination,
        conv = non_primitive_conv,
        nct = num_cast_type,
        cs1 = test_value_1,
        cs2 = test_value_2,
        cs3 = test_value_3,
    )
    .parse()
    .unwrap()
}

fn configure_test_specific_section<T: Display>(name: &str, len_diff: bool, num_diff: T) -> String {
    if len_diff {
        format!(
            "
        fundamental_default.{nm} = fundamental_default.{nm} + {nd};
        ",
            nm = name,
            nd = num_diff
        )
    } else {
        format!(
            "
        fundamental_default = fundamental_default + {};
        ",
            num_diff
        )
    }
}

fn configure_prospective_non_primitive_conversion(alternative_data_type: &str) -> &str {
    match alternative_data_type.trim() {
        "u64" => "fundamental_default",
        "Duration" => "Duration::from_secs(fundamental_default)",
        x => unreachable!("'{}'", x),
    }
}
