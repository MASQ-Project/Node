// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

extern crate proc_macro;

use heck::CamelCase;
use proc_macro::TokenStream;
use syn;

pub fn quad_tests_computed_default_body(args: Vec<&str>) -> TokenStream {
    let name = args[0];
    let early_default = args[1];
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
    let fundamental_default_len = fundamental_default.len();
    let length_differ = early_default.len() != fundamental_default_len;
    let default_location = if length_differ {
        format!("{}.{}", fundamental_default, name)
    } else {
        fundamental_default.clone()
    };
    let conflict_section = configure_conflict_section(name, length_differ);
    let non_primitive_conversion =
        configure_computation_and_non_primitive_conversion(alternative_data_type);
    format!(
        "
    #[test]
    fn {nm}_computed_default_all_absent(){{
        let subject = {nmcc}{{}};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &None,
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
    fn {nm}_computed_default_bootstrapper_config_absent_persistent_value_equal_to_default() {{
        let subject = {nmcc}{{}};
        let persistent_config = PersistentConfigurationMock::default()
            .{nm}_result(Ok(
                {dfl} as {ct}
                ));

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &Some(Box::new(persistent_config)),
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
                   ({dfl} + 555) as u64
                )
            );

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            &Some(Box::new(persistent_config)),
            &None,
        );

        assert_eq!(
            result,
            Some((
                (({dfl} + 555) as u64).to_string(),
                Configured
            ))
        )
    }}

    #[test]
    fn {nm}_computed_default_bootstrapper_config_present_persistent_config_present() {{
        let subject = {nmcc}{{}};
        let persistent_config = PersistentConfigurationMock::default()
            .{nm}_result(Ok(({dfl} + 555) as u64));
        let mut bootstrapper_config = BootstrapperConfig::new();
        let mut fundamental_default = {fd}.clone();
        {cs}
        bootstrapper_config.{bcd} = Some({conv});

        let result = subject.computed_default(
            &bootstrapper_config,
            &Some(Box::new(persistent_config)),
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
        ct = num_cast_type,
        fd = fundamental_default,
        cs = conflict_section,
        bcd = bootstrapper_config_destination,
        conv = non_primitive_conversion
    )
    .parse()
    .unwrap()
}

fn configure_conflict_section(name: &str, len_diff: bool) -> String {
    if len_diff {
        format!(
            "
        fundamental_default.{nm} = fundamental_default.{nm} + 12345;
        ",
            nm = name,
        )
    } else {
        "
        fundamental_default = fundamental_default + 12345;
        "
        .to_string()
    }
}

fn configure_computation_and_non_primitive_conversion(alternative_data_type: &str) -> &str {
    match alternative_data_type.trim() {
        "u64" => "fundamental_default",
        "Duration" => "Duration::from_secs(fundamental_default)",
        x => unreachable!("'{}'", x),
    }
}
