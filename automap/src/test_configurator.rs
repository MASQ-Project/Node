use masq_lib::utils::localhost;
use std::net::TcpListener;

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct TestConfig {
    pub test_to_run: [bool; 3],
    pub port: Option<u16>,
    pub no_remove: bool,
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
                })
            }
            name if &*(name.as_ref().unwrap()) == "igdp" => [true, false, false],
            name if &*(name.as_ref().unwrap()) == "pmp" => [false, false, true],
            name if &*(name.as_ref().unwrap()) == "pcp" => [false, true, false],
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::utils::localhost;
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
                no_remove: false
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
                no_remove: false
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
                    test_to_run: [false, true, false],
                    port: None,
                    no_remove: false
                }),
                Ok(TestConfig {
                    test_to_run: [false, false, true],
                    port: None,
                    no_remove: false
                }),
                Ok(TestConfig {
                    test_to_run: [true, false, false],
                    port: None,
                    no_remove: false
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
                test_to_run: [true, false, false],
                port: Some(16000),
                no_remove: false
            })
        )
    }

    #[test]
    fn build_test_config_specific_test_including_specific_port_but_bad_port() {
        let _ = TcpListener::bind(format!("{}:{}", localhost(), 40)).unwrap();

        let args = vec!["automap".to_string(), "igdp".to_string(), "40".to_string()];

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
    fn build_test_config_with_all_params_supplied_works() {
        let args = vec![
            "automap".to_string(),
            "igdp".to_string(),
            "16444".to_string(),
            "noremove".to_string(),
        ];

        let result = build_test_config(args);

        assert_eq!(
            result,
            Ok(TestConfig {
                test_to_run: [true, false, false],
                port: Some(16444),
                no_remove: true
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
}
