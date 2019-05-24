// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::logger::Logger;
use clap::{App, ArgMatches};
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use toml::value::Table;
use toml::Value;

macro_rules! value_m {
    ($m:ident, $v:expr, $t:ty) => {{
        let matches = $m.arg_matches();
        match value_t!(matches, $v, $t) {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }};
}

macro_rules! values_m {
    ($m:ident, $v:expr, $t:ty) => {{
        let matches = $m.arg_matches();
        match values_t!(matches, $v, $t) {
            Ok(vs) => vs,
            Err(_) => vec![],
        }
    }};
}

pub struct MultiConfig<'a> {
    arg_matches: ArgMatches<'a>,
}

impl<'a> MultiConfig<'a> {
    /// Create a new MultiConfig that can be passed into the value_m! and values_m! macros, containing
    /// several VirtualCommandLine objects in increasing priority order. That is, values found in
    /// VirtualCommandLine objects placed later in the list will override values found in
    /// VirtualCommandLine objects placed earlier.
    pub fn new(schema: &App<'a, 'a>, vcls: Vec<Box<VirtualCommandLine>>) -> MultiConfig<'a> {
        let initial: Box<VirtualCommandLine> = Box::new(CommandLineVCL::new(vec![String::new()]));
        let merged = vcls
            .into_iter()
            .fold(initial, |so_far, vcl| merge(so_far, vcl));
        MultiConfig {
            arg_matches: schema
                .clone()
                .get_matches_from_safe(merged.args().into_iter())
                .unwrap_or_else(|e| panic!("{}", e)),
        }
    }

    pub fn arg_matches(&'a self) -> &ArgMatches<'a> {
        &self.arg_matches
    }
}

pub trait VclArg: Debug {
    fn name(&self) -> &str;
    fn value(&self) -> &str;
    fn to_args(&self) -> Vec<String>;
    fn dup(&self) -> Box<VclArg>;
}

fn vcl_args_to_args(vcl_args: &Vec<Box<VclArg>>) -> Vec<String> {
    vec![String::new()] // ersatz command
        .into_iter()
        .chain(vcl_args.iter().flat_map(|va| va.to_args()))
        .collect()
}

fn vcl_args_to_vcl_args(vcl_args: &Vec<Box<VclArg>>) -> Vec<&VclArg> {
    vcl_args.iter().map(|box_ref| box_ref.as_ref()).collect()
}

#[derive(Clone, Debug)]
pub struct NameValueVclArg {
    name: String,
    value: String,
}

impl VclArg for NameValueVclArg {
    fn name(&self) -> &str {
        &self.name
    }

    fn value(&self) -> &str {
        &self.value
    }

    fn to_args(&self) -> Vec<String> {
        vec![self.name.clone(), self.value.clone()]
    }

    fn dup(&self) -> Box<VclArg> {
        Box::new(NameValueVclArg::new(self.name(), self.value()))
    }
}

impl NameValueVclArg {
    pub fn new(name: &str, value: &str) -> NameValueVclArg {
        NameValueVclArg {
            name: String::from(name),
            value: String::from(value),
        }
    }
}

pub trait VirtualCommandLine {
    fn vcl_args(&self) -> Vec<&VclArg>;
    fn args(&self) -> Vec<String>;
}

pub fn merge(
    lower_priority: Box<VirtualCommandLine>,
    higher_priority: Box<VirtualCommandLine>,
) -> Box<VirtualCommandLine> {
    let combined_vcl_args = higher_priority
        .vcl_args()
        .into_iter()
        .chain(lower_priority.vcl_args().into_iter())
        .collect::<Vec<&VclArg>>();
    let mut names = combined_vcl_args
        .iter()
        .map(|vcl_arg| vcl_arg.name().to_string())
        .collect::<HashSet<String>>();
    let prioritized_vcl_args = combined_vcl_args
        .into_iter()
        .filter(|vcl_arg| {
            let name = vcl_arg.name().to_string();
            if names.contains(&name) {
                names.remove(&name);
                true
            } else {
                false
            }
        })
        .map(|vcl_arg_ref| vcl_arg_ref.dup())
        .collect::<Vec<Box<VclArg>>>();
    Box::new(CommandLineVCL {
        vcl_args: prioritized_vcl_args,
    })
}

pub struct CommandLineVCL {
    vcl_args: Vec<Box<VclArg>>,
}

impl VirtualCommandLine for CommandLineVCL {
    fn vcl_args(&self) -> Vec<&VclArg> {
        vcl_args_to_vcl_args(&self.vcl_args)
    }

    fn args(&self) -> Vec<String> {
        vcl_args_to_args(&self.vcl_args)
    }
}

impl CommandLineVCL {
    pub fn new(mut args: Vec<String>) -> CommandLineVCL {
        args.remove(0); // remove command
        let chunks = args.chunks_exact(2);
        let vcl_args = chunks
            .into_iter()
            .map(|chunk| {
                let result: Box<VclArg> = Box::new(NameValueVclArg::new(&chunk[0], &chunk[1]));
                result
            })
            .collect();
        CommandLineVCL { vcl_args }
    }
}

pub struct EnvironmentVCL {
    vcl_args: Vec<Box<VclArg>>,
}

impl VirtualCommandLine for EnvironmentVCL {
    fn vcl_args(&self) -> Vec<&VclArg> {
        vcl_args_to_vcl_args(&self.vcl_args)
    }

    fn args(&self) -> Vec<String> {
        vcl_args_to_args(&self.vcl_args)
    }
}

impl EnvironmentVCL {
    pub fn new<'a>(schema: &App<'a, 'a>) -> EnvironmentVCL {
        let opt_names: HashSet<String> = schema
            .p
            .opts
            .iter()
            .map(|opt| opt.b.name.to_string())
            .collect();
        let mut vcl_args: Vec<Box<VclArg>> = vec![];
        for (upper_name, value) in std::env::vars() {
            if (upper_name.len() < 4) || (&upper_name[0..4] != "SUB_") {
                continue;
            }
            let lower_name = upper_name[4..].to_lowercase();
            if opt_names.contains(&lower_name) {
                let name = format!("--{}", lower_name);
                vcl_args.push(Box::new(NameValueVclArg::new(&name, &value)));
            }
        }
        EnvironmentVCL { vcl_args }
    }
}

pub struct ConfigFileVCL {
    vcl_args: Vec<Box<VclArg>>,
    _logger: Logger,
}

impl VirtualCommandLine for ConfigFileVCL {
    fn vcl_args(&self) -> Vec<&VclArg> {
        vcl_args_to_vcl_args(&self.vcl_args)
    }

    fn args(&self) -> Vec<String> {
        vcl_args_to_args(&self.vcl_args)
    }
}

impl ConfigFileVCL {
    pub fn new(file_path: &PathBuf, user_specified: bool) -> ConfigFileVCL {
        let logger = Logger::new("Bootstrapper");
        let mut file: File = match File::open(file_path) {
            Err(e) => {
                if user_specified {
                    panic!(
                        "Configuration file at {:?} could not be read: {}",
                        file_path, e
                    )
                } else {
                    logger.info(format!(
                        "No configuration file was found at {} - skipping",
                        file_path.display()
                    ));
                    return ConfigFileVCL {
                        vcl_args: vec![],
                        _logger: logger,
                    };
                }
            }
            Ok(file) => file,
        };
        let mut contents = String::new();
        match file.read_to_string(&mut contents) {
            Err (ref e) if e.kind() == ErrorKind::InvalidData => panic! ("Configuration file at {:?} is corrupted: contains data that cannot be interpreted as UTF-8", file_path),
            Err (e) => panic! ("Configuration file at {:?}: {}", file_path, e),
            Ok (_) => (),
        };
        let table: Table = match toml::de::from_str(&contents) {
            Err(e) => panic!(
                "Configuration file at {:?} has bad TOML syntax: {}",
                file_path, e
            ),
            Ok(table) => table,
        };
        let vcl_args: Vec<Box<VclArg>> = table
            .keys()
            .map(|key| {
                let name = format!("--{}", key);
                let value = match table.get(key).expect("value disappeared") {
                    Value::Table(_) => Self::complain_about_data_elements(file_path),
                    Value::Array(_) => Self::complain_about_data_elements(file_path),
                    Value::Datetime(_) => Self::complain_about_data_elements(file_path),
                    v => v.to_string(),
                };
                let result: Box<VclArg> = Box::new(NameValueVclArg::new(&name, &value.to_string()));
                result
            })
            .collect();

        ConfigFileVCL {
            vcl_args,
            _logger: logger,
        }
    }

    fn complain_about_data_elements(file_path: &PathBuf) -> ! {
        panic! ("Configuration file at {:?} contains unsupported Datetime or non-scalar configuration values", file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::test_utils::ensure_node_home_directory_exists;
    use clap::Arg;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn double_provided_optional_single_valued_parameter_with_no_default_produces_second_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(false),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "10".to_string(),
            ])),
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric_arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn first_provided_optional_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(false),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20".to_string(),
            ])),
            Box::new(CommandLineVCL::new(vec![String::new()])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric_arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn second_provided_optional_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(false),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![String::new()])),
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric_arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn double_provided_optional_multivalued_parameter_with_no_default_produces_second_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .use_delimiter(true),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "10,11".to_string(),
            ])),
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20,21".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = values_m!(subject, "numeric_arg", u64);

        assert_eq!(vec![20, 21], result);
    }

    #[test]
    fn first_provided_optional_multivalued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .use_delimiter(true),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20,21".to_string(),
            ])),
            Box::new(CommandLineVCL::new(vec![String::new()])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = values_m!(subject, "numeric_arg", u64);

        assert_eq!(vec![20, 21], result);
    }

    #[test]
    fn second_provided_optional_multivalued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .use_delimiter(true),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![String::new()])),
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20,21".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = values_m!(subject, "numeric_arg", u64);

        assert_eq!(vec![20, 21], result);
    }

    #[test]
    fn first_provided_required_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(true),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20".to_string(),
            ])),
            Box::new(CommandLineVCL::new(vec![String::new()])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric_arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn second_provided_required_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true)
                .required(true),
        );
        let vcls: Vec<Box<VirtualCommandLine>> = vec![
            Box::new(CommandLineVCL::new(vec![String::new()])),
            Box::new(CommandLineVCL::new(vec![
                String::new(),
                "--numeric_arg".to_string(),
                "20".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric_arg", u64);

        assert_eq!(Some(20), result);
    }

    //////

    #[test]
    fn environment_vcl_works() {
        let _guard = EnvironmentGuard::new();
        let schema = App::new("test").arg(
            Arg::with_name("numeric_arg")
                .long("numeric_arg")
                .takes_value(true),
        );
        std::env::set_var("SUB_NUMERIC_ARG", "47");

        let subject = EnvironmentVCL::new(&schema);

        assert_eq!(
            vec![
                "".to_string(),
                "--numeric_arg".to_string(),
                "47".to_string()
            ],
            subject.args()
        );
        assert_eq!(
            vec![("--numeric_arg", "47")],
            subject
                .vcl_args()
                .into_iter()
                .map(|vcl_arg| (vcl_arg.name(), vcl_arg.value()))
                .collect::<Vec<(&str, &str)>>()
        );
    }

    #[test]
    fn config_file_vcl_works() {
        let home_dir = ensure_node_home_directory_exists("multi_config", "config_file_vcl_works");
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");
        {
            let mut toml_file = File::create(&file_path).unwrap();
            toml_file.write_all(b"numeric_arg = 47\n").unwrap();
        }

        let subject = ConfigFileVCL::new(&file_path, true);

        assert_eq!(
            vec![
                "".to_string(),
                "--numeric_arg".to_string(),
                "47".to_string()
            ],
            subject.args()
        );
        assert_eq!(
            vec![("--numeric_arg", "47")],
            subject
                .vcl_args()
                .into_iter()
                .map(|vcl_arg| (vcl_arg.name(), vcl_arg.value()))
                .collect::<Vec<(&str, &str)>>()
        );
    }

    #[test]
    fn config_file_vcl_handles_missing_file_when_not_user_specified() {
        init_test_logging();
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_handles_missing_file_when_not_user_specified",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");

        let subject = ConfigFileVCL::new(&file_path, false);

        assert_eq!(vec!["".to_string()], subject.args());
        assert!(subject.vcl_args().is_empty());
        TestLogHandler::new().exists_log_matching(
            "INFO: Bootstrapper: No configuration file was found at .+ - skipping",
        );
    }

    #[test]
    #[should_panic(expected = "could not be read: ")]
    fn config_file_vcl_panics_about_missing_file_when_user_specified() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_panics_about_missing_file_when_user_specified",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");

        ConfigFileVCL::new(&file_path, true);
    }

    #[test]
    #[should_panic(expected = "is corrupted: contains data that cannot be interpreted as UTF-8")]
    fn config_file_vcl_handles_non_utf8_contents() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_handles_non_utf8_contents",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");
        {
            let mut toml_file = File::create(&file_path).unwrap();
            // UTF-8 doesn't tolerate 192 followed by 193
            let mut buf: Vec<u8> = vec![1, 2, 3, 32, 192, 193, 32, 4, 5];
            toml_file.write_all(&mut buf).unwrap();
        }

        ConfigFileVCL::new(&file_path, true);
    }

    #[test]
    #[should_panic(
        expected = "has bad TOML syntax: expected a table key, found a right bracket at line 1"
    )]
    fn config_file_vcl_handles_non_toml_contents() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_handles_non_toml_contents",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");
        {
            let mut toml_file = File::create(&file_path).unwrap();
            toml_file.write_all(b"][=blah..[\n").unwrap();
        }

        ConfigFileVCL::new(&file_path, true);
    }

    #[test]
    #[should_panic(expected = "contains unsupported Datetime or non-scalar configuration values")]
    fn config_file_vcl_handles_datetime_element() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_handles_datetime_element",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");
        {
            let mut toml_file = File::create(&file_path).unwrap();
            toml_file.write_all(b"datetime = 12:34:56\n").unwrap();
        }

        ConfigFileVCL::new(&file_path, true);
    }

    #[test]
    #[should_panic(expected = "contains unsupported Datetime or non-scalar configuration values")]
    fn config_file_vcl_handles_array_element() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_handles_array_element",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");
        {
            let mut toml_file = File::create(&file_path).unwrap();
            toml_file.write_all(b"array = [1, 2, 3]\n").unwrap();
        }

        ConfigFileVCL::new(&file_path, true);
    }

    #[test]
    #[should_panic(expected = "contains unsupported Datetime or non-scalar configuration values")]
    fn config_file_vcl_handles_table_element() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_handles_table_element",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");
        {
            let mut toml_file = File::create(&file_path).unwrap();
            toml_file.write_all(b"[table]\nooga = \"booga\"").unwrap();
        }

        ConfigFileVCL::new(&file_path, true);
    }
}
