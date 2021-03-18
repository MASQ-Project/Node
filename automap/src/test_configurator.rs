use masq_lib::utils::localhost;
use std::net::TcpListener;

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct TestConfig {
    pub test_to_run: [bool; 3],
    pub port: Option<u16>,
    pub no_remove: bool,
    pub open_port_time_period: Option<u32>,
}

pub fn build_test_config(args: Vec<String>) -> Result<TestConfig, String> {
    let mut pure_args = args
        .into_iter()
        .skip(1)
        .skip_while(|elem| elem.trim() == "automap");
    Ok(TestConfig {
        test_to_run: match pure_args.next() {
            name if name.is_none() => {
                return Ok(TestConfig {
                    test_to_run: [true, true, true],
                    port: None,
                    no_remove: false,
                    open_port_time_period: None,
                })
            }
            name if &*(name.as_ref().unwrap()) == "igdp" => [false, false, true],
            name if &*(name.as_ref().unwrap()) == "pmp" => [false, true, false],
            name if &*(name.as_ref().unwrap()) == "pcp" => [true, false, false],
            name => return Err(format!("Unknown argument: {}", name.unwrap())),
        },
        port: match pure_args.next() {
            Some(value) => match value.parse::<u16>() {
                Ok(port) => match TcpListener::bind(format!("{}:{}", localhost(), port)) {
                    Ok(_) => Some(port),
                    Err(_) => return Err("The chosen port is not free".to_string()),
                },
                Err(e) => return Err(format!("Port: {}", e)),
            },
            None => None,
        },
        no_remove: match pure_args.next() {
            None => false,
            Some(value) if &value == "noremove" => true,
            arg if arg.is_some() => return Err(format!("Unknown argument: {}", arg.unwrap())),
            _ => unreachable!(),
        },
        open_port_time_period: match pure_args.next() {
            None => None,
            Some(value) => match value.parse::<u32>() {
                Ok(timeout) => Some(timeout),
                Err(e) => return Err(format!("Open port time limit: {}", e)),
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::utils::{find_free_port, localhost};
    use std::net::TcpListener;

    #[test]
    fn build_test_config_for_standard_automap() {
        let args = vec!["C:\\Users\\Public".to_string(), "automap".to_string()];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Ok(TestConfig {
                test_to_run: [true, true, true],
                port: None,
                no_remove: false,
                open_port_time_period: None
            })
        )
    }

    #[test]
    fn build_test_config_for_standard_automap_not_counting_path() {
        let args = vec!["automap".to_string()];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Ok(TestConfig {
                test_to_run: [true, true, true],
                port: None,
                no_remove: false,
                open_port_time_period: None
            })
        )
    }

    #[test]
    fn build_test_config_returns_error_if_unknown_parameter_after_automap() {
        let args = vec!["automap".to_string(), "super_test".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Err("Unknown argument: super_test".to_string()))
    }

    #[test]
    fn build_test_config_allows_to_choose_specific_test_type_and_returns_configuration_because_no_other_args_supplied(
    ) {
        let args_collection = vec![
            vec!["automap".to_string(), "pcp".to_string()],
            vec!["automap".to_string(), "pmp".to_string()],
            vec!["automap".to_string(), "igdp".to_string()],
        ];

        let results = args_collection
            .into_iter()
            .map(|vec| build_test_config(vec))
            .collect::<Vec<_>>();

        assert_eq!(
            results,
            vec![
                Ok(TestConfig {
                    test_to_run: [true, false, false],
                    port: None,
                    no_remove: false,
                    open_port_time_period: None
                }),
                Ok(TestConfig {
                    test_to_run: [false, true, false],
                    port: None,
                    no_remove: false,
                    open_port_time_period: None
                }),
                Ok(TestConfig {
                    test_to_run: [false, false, true],
                    port: None,
                    no_remove: false,
                    open_port_time_period: None
                }),
            ]
        )
    }

    #[test]
    fn build_test_config_specific_test_including_specific_port_which_is_free() {
        let args = vec![
            "path".to_string(),
            "automap".to_string(),
            "igdp".to_string(),
            "16000".to_string(),
        ];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Ok(TestConfig {
                test_to_run: [false, false, true],
                port: Some(16000),
                no_remove: false,
                open_port_time_period: None
            })
        )
    }

    #[test]
    fn build_test_config_specific_test_including_specific_port_but_bad_port() {
        let port = find_free_port();
        let _blocker = TcpListener::bind(format!("{}:{}", localhost(), port)).unwrap();

        let args = vec!["automap".to_string(), "igdp".to_string(), port.to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Err("The chosen port is not free".to_string()))
    }

    #[test]
    fn build_test_config_specific_test_including_specific_port_but_cannot_produce_a_number() {
        let args = vec![
            "automap".to_string(),
            "igdp".to_string(),
            "45kk".to_string(),
        ];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Err("Port: invalid digit found in string".to_string())
        )
    }

    #[test]
    fn build_test_config_works_with_all_params_except_open_port_time_param() {
        //this setting implies the former value hardcoded for the open port interval
        let port = find_free_port();
        let args = vec![
            "automap".to_string(),
            "igdp".to_string(),
            port.to_string(),
            "noremove".to_string(),
        ];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Ok(TestConfig {
                test_to_run: [false, false, true],
                port: Some(port),
                no_remove: true,
                open_port_time_period: None
            })
        )
    }

    #[test]
    fn build_test_config_with_all_params_supplied_but_misspelled_3rd_value() {
        let args = vec![
            "automap".to_string(),
            "igdp".to_string(),
            "16444".to_string(),
            "norrrrremove".to_string(),
        ];

        let result = build_test_config(args);

        assert_eq!(result, Err("Unknown argument: norrrrremove".to_string()))
    }

    #[test]
    fn build_test_config_works_with_all_params_supplied() {
        let port = find_free_port();
        let args = vec![
            "automap".to_string(),
            "igdp".to_string(),
            port.to_string(),
            "noremove".to_string(),
            "600".to_string(),
        ];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Ok(TestConfig {
                test_to_run: [false, false, true],
                port: Some(port),
                no_remove: true,
                open_port_time_period: Some(600)
            })
        )
    }

    #[test]
    fn build_test_config_catch_an_error_internally_at_the_last_parameter() {
        let port = find_free_port();
        let args = vec![
            "automap".to_string(),
            "igdp".to_string(),
            port.to_string(),
            "noremove".to_string(),
            "9999999999".to_string(),
        ];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Err("Open port time limit: number too large to fit in target type".to_string())
        )
    }
}
