// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

extern crate proc_macro;

use heck::CamelCase;
use proc_macro::TokenStream;
use std::fmt::Display;

pub fn triple_test_computed_default_body(args: Vec<&str>) -> TokenStream {
    let parameter_name = args[0];
    let num_cast_type = args[1];
    let group = args[2];
    let group = group.trim().parse().expect("parsing number");
    let fundamental_default = match group {
        1 => "DEFAULT_PAYMENT_CURVES",
        2 => "DEFAULT_RATE_PACK",
        3 => {
            if parameter_name.contains("pending") {
                "DEFAULT_PENDING_PAYMENT_SCAN_INTERVAL"
            } else if parameter_name.contains("receivable") {
                "DEFAULT_RECEIVABLE_SCAN_INTERVAL"
            } else {
                "DEFAULT_PAYABLE_SCAN_INTERVAL"
            }
        }
        x => panic!("only numbers 1, 2, 3 are allowed, not {}", x),
    };
    let name_camel_case = parameter_name.to_camel_case();
    let default_location = match group {
        1 | 2 => format!("{}.{}", fundamental_default, parameter_name),
        3 => fundamental_default.to_string(),
        _ => unreachable!(),
    };
    let bootstrapper_conf_location = match group {
        1 => format!(
            "accountant_config_opt.as_mut().unwrap().payment_curves.{}",
            parameter_name
        ),
        2 => format!("rate_pack_opt.as_mut().unwrap().{}", parameter_name),
        3 => format!("accountant_config_opt.as_mut().unwrap().{}", parameter_name),
        _ => unreachable!(),
    };
    let populate_bootstrapper_config_with_some = match group{
        1 | 3 => "bootstrapper_config.accountant_config_opt = Some(make_populated_accountant_config_with_defaults());",
        2 => "bootstrapper_config.rate_pack_opt = Some(DEFAULT_RATE_PACK);",
        _ => unreachable!()
    };
    let test_value_1 = test_specific_value(parameter_name, group, 0);
    let test_value_2 = test_specific_value(parameter_name, group, 555);
    let test_value_3 = test_specific_value(parameter_name, group, 1000);
    let non_primitive_conv = match group {
        1 | 2 => "adjusted_default".to_string(),
        3 => "Duration::from_secs(adjusted_default)".to_string(),
        _ => unreachable!(),
    };
    format!(
        "
    #[test]
    fn {nm}_computed_default_all_defaulted(){{
        let subject = {nmcc}{{}};
        let mut bootstrapper_config = BootstrapperConfig::new();
        {pbc}
        let mut fundamental_default = {fd}.clone();
        {cs1}
        bootstrapper_config.{bcd} = {conv};

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
        {pbc}
        let mut fundamental_default = {fd}.clone();
        {cs2}
        bootstrapper_config.{bcd} = {conv};

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
        {pbc}
        let mut fundamental_default = {fd}.clone();
        {cs3}
        bootstrapper_config.{bcd} = {conv};
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
        nm = parameter_name,
        nmcc = name_camel_case,
        dfl = default_location,
        fd = fundamental_default,
        bcd = bootstrapper_conf_location,
        pbc = populate_bootstrapper_config_with_some,
        conv = non_primitive_conv,
        nct = num_cast_type,
        cs1 = test_value_1,
        cs2 = test_value_2,
        cs3 = test_value_3,
    )
    .parse()
    .expect("parsing into Rust code failed")
}

fn test_specific_value<T: Display>(name: &str, group: u8, num_diff: T) -> String {
    match group {
        1 | 2 => format!(
            "let adjusted_default = fundamental_default.{nm} + {nd};",
            nm = name,
            nd = num_diff
        ),
        3 => format!("let adjusted_default = fundamental_default + {};", num_diff),
        _ => unreachable!(),
    }
}
