// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

extern crate proc_macro;

use heck::CamelCase;
use proc_macro::TokenStream;
use std::fmt::Display;

pub fn triple_test_computed_default_impl(args: Vec<&str>) -> TokenStream {
    let parameter_name = args[0];
    let num_cast_type = args[1];
    let group = args[2];
    let group = group.trim().parse().expect("parsing number");
    let fundamental_default = match group {
        1 => "DEFAULT_PAYMENT_CURVES".to_string(),
        2 => "DEFAULT_RATE_PACK".to_string(),
        3 => format!("DEFAULT_{}", parameter_name.to_uppercase()),
        x => panic!("only numbers 1, 2, 3 are allowed, not {}", x),
    };
    let name_camel_case = parameter_name.to_camel_case();
    let in_default_location = match group {
        1 | 2 => format!("{}.{}", fundamental_default, parameter_name),
        3 => fundamental_default.to_string(),
        _ => unreachable!(),
    };
    let bootstrapper_conf_location = match group {
        1 => format!(
            "accountant_config_opt.as_mut().unwrap().payment_curves.{}",
            parameter_name
        ),
        2 => format!("neighborhood_config.mode.rate_pack().{}", parameter_name),
        3 => format!("accountant_config_opt.as_mut().unwrap().{}", parameter_name),
        _ => unreachable!(),
    };
    let populate_bc_with_some_val = match group{
        1 | 3 => "bootstrapper_config.accountant_config_opt = Some(make_populated_accountant_config_with_defaults());",
        2 => "", //specific, omitting
        _ => unreachable!()
    };
    let test_value_1 = test_specific_value(parameter_name, &fundamental_default, group, 0);
    let test_value_2 = test_specific_value(parameter_name, &fundamental_default, group, 555);
    let test_value_3 = test_specific_value(parameter_name, &fundamental_default, group, 1000);
    let non_primitive_conv = match group {
        1 | 2 => "adjusted_default".to_string(),
        3 => "Duration::from_secs(adjusted_default)".to_string(),
        _ => unreachable!(),
    };
    let final_bc_readiness = match group {
        1 | 3 => format!(
            "bootstrapper_config.{bootstrapper_conf_location} = {non_primitive_conv};",
            bootstrapper_conf_location = bootstrapper_conf_location,
            non_primitive_conv = non_primitive_conv
        ),
        2 => format!(
            "bootstrapper_config.neighborhood_config.mode = {non_primitive_conv};",
            non_primitive_conv = non_primitive_conv
        ),
        _ => unreachable!(),
    };
    format!(
        "
    #[test]
    fn {parameter_name}_computed_default_all_defaulted(){{
        let subject = {name_camel_case}{{}};
        let mut bootstrapper_config = BootstrapperConfig::new();
        {populate_bc_with_some_val}
        {test_value_1}
        {final_bc_readiness};

        let result = subject.computed_default(
            &bootstrapper_config,
            &make_persistent_config_real_with_config_dao_null(),
            &None,
        );

        assert_eq!(
            result,
            Some((
                {in_default_location}.to_string(),
                Default
            ))
        )
    }}

    #[test]
    fn {parameter_name}_computed_default_bootstrapper_config_absent_persistent_value_unequal_to_default() {{
        let subject = {name_camel_case}{{}};
        let persistent_config = PersistentConfigurationMock::default()
            .{parameter_name}_result(
                Ok(
                   ({in_default_location} + 555) as {num_cast_type})
            );
        let mut bootstrapper_config = BootstrapperConfig::new();
        {populate_bc_with_some_val}
        {test_value_2}
        {final_bc_readiness};

        let result = subject.computed_default(
            &bootstrapper_config,
            &persistent_config,
            &None,
        );

        assert_eq!(
            result,
            Some((
                ({in_default_location} + 555).to_string(),
                Configured
            ))
        )
    }}

    #[test]
    fn {parameter_name}_computed_default_bootstrapper_config_different_from_persistent_config_value() {{
        let subject = {name_camel_case}{{}};
        let persistent_config = PersistentConfigurationMock::default()
            .{parameter_name}_result(Ok(({in_default_location} + 555) as {num_cast_type}));
        let mut bootstrapper_config = BootstrapperConfig::new();
        {populate_bc_with_some_val}
        {test_value_3}
        {final_bc_readiness};
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
        parameter_name = parameter_name,
        name_camel_case = name_camel_case,
        in_default_location = in_default_location,
        populate_bc_with_some_val = populate_bc_with_some_val,
        final_bc_readiness = final_bc_readiness,
        num_cast_type = num_cast_type,
        test_value_1 = test_value_1,
        test_value_2 = test_value_2,
        test_value_3 = test_value_3,
    )
    .parse()
    .expect("parsing into Rust code failed")
}

fn test_specific_value<T: Display>(
    parameter_name: &str,
    fundamental_default: &str,
    group: u8,
    num_diff: T,
) -> String {
    match group {
        1 => format!(
            "let fundamental_default = {fundamental_default}.clone();
             let adjusted_default = fundamental_default.{parameter_name} + {num_diff};",
            fundamental_default = fundamental_default,
            parameter_name = parameter_name,
            num_diff = num_diff
        ),
        2 => format!(
            "\
        let mut rate_pack = DEFAULT_RATE_PACK;
        rate_pack.{parameter_name} = rate_pack.{parameter_name} + {num_diff};
        let neighbor =
        NodeDescriptor::try_from((main_cryptde(), \"masq://eth-mainnet:AgMEBQ@2.3.4.5:2345\"))
        .unwrap();
        let adjusted_default = Standard(
            NodeAddr::new(&localhost(), &[1234]),
            vec![neighbor],
            rate_pack,
        );\
        ",
            parameter_name = parameter_name,
            num_diff = num_diff
        ),
        3 => format!(
            "let fundamental_default = {fundamental_default}.clone();
             let adjusted_default = fundamental_default + {num_diff};",
            fundamental_default = fundamental_default,
            num_diff = num_diff
        ),
        _ => unreachable!(),
    }
}
