// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

#[allow(unused_imports)]
use clap::{value_t, values_t};
use clap::{App, ArgMatches};
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use toml::value::Table;
use toml::Value;

#[macro_export]
macro_rules! value_m {
    ($m:ident, $v:expr, $t:ty) => {{
        let matches = $m.arg_matches();
        match value_t!(matches, $v, $t) {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }};
}

#[macro_export]
macro_rules! value_user_specified_m {
    ($m:ident, $v:expr, $t:ty) => {{
        let matches = $m.arg_matches();
        let user_specified = matches.occurrences_of($v) > 0;
        match value_t!(matches, $v, $t) {
            Ok(v) => (Some(v), user_specified),
            Err(_) => (None, user_specified),
        }
    }};
}

#[macro_export]
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
    pub fn new(schema: &App<'a, 'a>, vcls: Vec<Box<dyn VirtualCommandLine>>) -> MultiConfig<'a> {
        let initial: Box<dyn VirtualCommandLine> =
            Box::new(CommandLineVcl::new(vec![String::new()]));
        let merged = vcls
            .into_iter()
            .fold(initial, |so_far, vcl| merge(so_far, vcl));
        MultiConfig {
            arg_matches: schema
                .clone()
                .get_matches_from_safe(merged.args().into_iter())
                .unwrap_or_else(Self::abort),
        }
    }

    pub fn arg_matches(&'a self) -> &ArgMatches<'a> {
        &self.arg_matches
    }

    fn abort(e: clap::Error) -> ArgMatches<'a> {
        // This doesn't appear to work. I don't know why not.
        if cfg!(test) {
            panic!("{:?}. --panic to catch for testing--", e)
        } else {
            // panic! ("{:?}", e); // uncomment during testing
            e.exit();
        }
    }
}

pub trait VclArg: Debug {
    fn name(&self) -> &str;
    fn to_args(&self) -> Vec<String>;
    fn dup(&self) -> Box<dyn VclArg>;
}

fn vcl_args_to_args(vcl_args: &[Box<dyn VclArg>]) -> Vec<String> {
    vec![String::new()] // ersatz command
        .into_iter()
        .chain(vcl_args.iter().flat_map(|va| va.to_args()))
        .collect()
}

fn vcl_args_to_vcl_args(vcl_args: &[Box<dyn VclArg>]) -> Vec<&dyn VclArg> {
    vcl_args.iter().map(|box_ref| box_ref.as_ref()).collect()
}

#[derive(Debug, PartialEq)]
pub struct NameValueVclArg {
    name: String,
    value: String,
}

impl VclArg for NameValueVclArg {
    fn name(&self) -> &str {
        &self.name
    }

    fn to_args(&self) -> Vec<String> {
        vec![self.name.clone(), self.value.clone()]
    }

    fn dup(&self) -> Box<dyn VclArg> {
        Box::new(NameValueVclArg::new(self.name(), self.value.as_str()))
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

#[derive(Debug, PartialEq)]
pub struct NameOnlyVclArg {
    name: String,
}

impl VclArg for NameOnlyVclArg {
    fn name(&self) -> &str {
        &self.name
    }

    fn to_args(&self) -> Vec<String> {
        vec![self.name.clone()]
    }

    fn dup(&self) -> Box<dyn VclArg> {
        Box::new(NameOnlyVclArg::new(self.name.as_str()))
    }
}

impl NameOnlyVclArg {
    pub fn new(name: &str) -> NameOnlyVclArg {
        NameOnlyVclArg {
            name: String::from(name),
        }
    }
}

pub trait VirtualCommandLine {
    fn vcl_args(&self) -> Vec<&dyn VclArg>;
    fn args(&self) -> Vec<String>;
}

pub fn merge(
    lower_priority: Box<dyn VirtualCommandLine>,
    higher_priority: Box<dyn VirtualCommandLine>,
) -> Box<dyn VirtualCommandLine> {
    let combined_vcl_args = higher_priority
        .vcl_args()
        .into_iter()
        .chain(lower_priority.vcl_args().into_iter())
        .collect::<Vec<&dyn VclArg>>();
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
        .collect::<Vec<Box<dyn VclArg>>>();
    Box::new(CommandLineVcl {
        vcl_args: prioritized_vcl_args,
    })
}

pub struct CommandLineVcl {
    vcl_args: Vec<Box<dyn VclArg>>,
}

impl VirtualCommandLine for CommandLineVcl {
    fn vcl_args(&self) -> Vec<&dyn VclArg> {
        vcl_args_to_vcl_args(&self.vcl_args)
    }

    fn args(&self) -> Vec<String> {
        vcl_args_to_args(&self.vcl_args)
    }
}

impl From<Vec<Box<dyn VclArg>>> for CommandLineVcl {
    fn from(vcl_args: Vec<Box<dyn VclArg>>) -> Self {
        CommandLineVcl { vcl_args }
    }
}

impl CommandLineVcl {
    pub fn new(mut args: Vec<String>) -> CommandLineVcl {
        args.remove(0); // remove command
        let mut vcl_args = vec![];
        while let Some(vcl_arg) = Self::next_vcl_arg(&mut args) {
            vcl_args.push(vcl_arg);
        }
        CommandLineVcl { vcl_args }
    }

    fn next_vcl_arg(args: &mut Vec<String>) -> Option<Box<dyn VclArg>> {
        if args.is_empty() {
            return None;
        }
        let name = args.remove(0);
        if !name.starts_with("--") {
            panic!("Expected option beginning with '--', not {}", name)
        }
        if args.is_empty() || args[0].starts_with("--") {
            Some(Box::new(NameOnlyVclArg::new(&name)))
        } else {
            let value = args.remove(0);
            Some(Box::new(NameValueVclArg::new(&name, &value)))
        }
    }
}

pub struct EnvironmentVcl {
    vcl_args: Vec<Box<dyn VclArg>>,
}

impl VirtualCommandLine for EnvironmentVcl {
    fn vcl_args(&self) -> Vec<&dyn VclArg> {
        vcl_args_to_vcl_args(&self.vcl_args)
    }

    fn args(&self) -> Vec<String> {
        vcl_args_to_args(&self.vcl_args)
    }
}

impl EnvironmentVcl {
    pub fn new<'a>(schema: &App<'a, 'a>) -> EnvironmentVcl {
        let opt_names: HashSet<String> = schema
            .p
            .opts
            .iter()
            .map(|opt| opt.b.name.to_string())
            .collect();
        let mut vcl_args: Vec<Box<dyn VclArg>> = vec![];
        for (upper_name, value) in std::env::vars() {
            if (upper_name.len() < 4) || (&upper_name[0..4] != "SUB_") {
                continue;
            }
            let lower_name = str::replace(&upper_name[4..].to_lowercase(), "_", "-");
            if opt_names.contains(&lower_name) {
                let name = format!("--{}", lower_name);
                vcl_args.push(Box::new(NameValueVclArg::new(&name, &value)));
            }
        }
        EnvironmentVcl { vcl_args }
    }
}

pub struct ConfigFileVcl {
    vcl_args: Vec<Box<dyn VclArg>>,
}

impl VirtualCommandLine for ConfigFileVcl {
    fn vcl_args(&self) -> Vec<&dyn VclArg> {
        vcl_args_to_vcl_args(&self.vcl_args)
    }

    fn args(&self) -> Vec<String> {
        vcl_args_to_args(&self.vcl_args)
    }
}

impl ConfigFileVcl {
    pub fn new(file_path: &PathBuf, user_specified: bool) -> ConfigFileVcl {
        let mut file: File = match File::open(file_path) {
            Err(e) => {
                if user_specified {
                    panic!(
                        "Configuration file at {:?} could not be read: {}",
                        file_path, e
                    )
                } else {
                    println!(
                        "No configuration file was found at {} - skipping",
                        file_path.display()
                    );
                    return ConfigFileVcl { vcl_args: vec![] };
                }
            }
            Ok(file) => file,
        };
        let mut contents = String::new();
        match file.read_to_string(&mut contents) {
            Err(ref e) if e.kind() == ErrorKind::InvalidData => panic!("Configuration file at {:?} is corrupted: contains data that cannot be interpreted as UTF-8", file_path),
            Err(e) => panic!("Configuration file at {:?}: {}", file_path, e),
            Ok(_) => (),
        };
        let table: Table = match toml::de::from_str(&contents) {
            Err(e) => panic!(
                "Configuration file at {:?} has bad TOML syntax: {}",
                file_path, e
            ),
            Ok(table) => table,
        };
        let vcl_args: Vec<Box<dyn VclArg>> = table
            .keys()
            .map(|key| {
                let name = format!("--{}", key);
                let value = match table.get(key).expect("value disappeared") {
                    Value::Table(_) => Self::complain_about_data_elements(file_path),
                    Value::Array(_) => Self::complain_about_data_elements(file_path),
                    Value::Datetime(_) => Self::complain_about_data_elements(file_path),
                    Value::String(v) => v.as_str().to_string(),
                    v => v.to_string(),
                };
                let result: Box<dyn VclArg> = Box::new(NameValueVclArg::new(&name, &value));
                result
            })
            .collect();

        ConfigFileVcl { vcl_args }
    }

    fn complain_about_data_elements(file_path: &PathBuf) -> ! {
        panic!("Configuration file at {:?} contains unsupported Datetime or non-scalar configuration values", file_path)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_utils::environment_guard::EnvironmentGuard;
    use crate::test_utils::utils::ensure_node_home_directory_exists;
    use clap::Arg;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn double_provided_optional_single_valued_parameter_with_no_default_produces_second_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(false),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "10".to_string(),
            ])),
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric-arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn first_provided_optional_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(false),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20".to_string(),
            ])),
            Box::new(CommandLineVcl::new(vec![String::new()])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric-arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn second_provided_optional_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(false),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![String::new()])),
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric-arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn double_provided_optional_multivalued_parameter_with_no_default_produces_second_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .use_delimiter(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "10,11".to_string(),
            ])),
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20,21".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = values_m!(subject, "numeric-arg", u64);

        assert_eq!(vec![20, 21], result);
    }

    #[test]
    fn first_provided_optional_multivalued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .use_delimiter(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20,21".to_string(),
            ])),
            Box::new(CommandLineVcl::new(vec![String::new()])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = values_m!(subject, "numeric-arg", u64);

        assert_eq!(vec![20, 21], result);
    }

    #[test]
    fn second_provided_optional_multivalued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .use_delimiter(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![String::new()])),
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20,21".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = values_m!(subject, "numeric-arg", u64);

        assert_eq!(vec![20, 21], result);
    }

    #[test]
    fn first_provided_required_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20".to_string(),
            ])),
            Box::new(CommandLineVcl::new(vec![String::new()])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric-arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn second_provided_required_single_valued_parameter_with_no_default_produces_provided_value() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![String::new()])),
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = value_m!(subject, "numeric-arg", u64);

        assert_eq!(Some(20), result);
    }

    #[test]
    fn first_provided_required_single_valued_parameter_with_no_default_produces_provided_value_with_user_specified_flag(
    ) {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20".to_string(),
            ])),
            Box::new(CommandLineVcl::new(vec![String::new()])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let (result, user_specified) = value_user_specified_m!(subject, "numeric-arg", u64);

        assert_eq!(Some(20), result);
        assert!(user_specified);
    }

    #[test]
    fn second_provided_required_single_valued_parameter_with_no_default_produces_provided_value_with_user_specified_flag(
    ) {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![String::new()])),
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--numeric-arg".to_string(),
                "20".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let (result, user_specified) = value_user_specified_m!(subject, "numeric-arg", u64);

        assert_eq!(Some(20), result);
        assert!(user_specified);
    }

    #[test]
    fn optional_single_valued_parameter_with_default_produces_provided_value_with_user_specified_flag(
    ) {
        let schema = App::new("test")
            .arg(
                Arg::with_name("numeric-arg")
                    .long("numeric-arg")
                    .takes_value(true)
                    .required(false)
                    .default_value("20"),
            )
            .arg(
                Arg::with_name("missing-arg")
                    .long("missing-arg")
                    .takes_value(true)
                    .required(false)
                    .default_value("88"),
            );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![Box::new(CommandLineVcl::new(vec![
            String::new(),
            "--numeric-arg".to_string(),
            "20".to_string(),
        ]))];
        let subject = MultiConfig::new(&schema, vcls);

        let (numeric_arg_result, user_specified_numeric) =
            value_user_specified_m!(subject, "numeric-arg", u64);
        let (missing_arg_result, user_specified_missing) =
            value_user_specified_m!(subject, "missing-arg", u64);

        assert_eq!(Some(20), numeric_arg_result);
        assert!(user_specified_numeric);
        assert_eq!(Some(88), missing_arg_result);
        assert!(!user_specified_missing);
        assert!(subject.arg_matches().is_present("missing-arg"));
    }

    #[test]
    fn existing_nonvalued_parameter_overrides_nonexistent_nonvalued_parameter() {
        let schema = App::new("test").arg(
            Arg::with_name("nonvalued")
                .long("nonvalued")
                .takes_value(false),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> = vec![
            Box::new(CommandLineVcl::new(vec![String::new()])),
            Box::new(CommandLineVcl::new(vec![
                String::new(),
                "--nonvalued".to_string(),
            ])),
        ];
        let subject = MultiConfig::new(&schema, vcls);

        let result = subject.arg_matches();

        assert!(result.is_present("nonvalued"));
    }

    #[test]
    #[should_panic(expected = "The following required arguments were not provided:")]
    fn clap_match_error_produces_panic() {
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true)
                .required(true),
        );
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(vec![String::new()]))];
        MultiConfig::new(&schema, vcls);
    }

    //////

    #[test]
    fn command_line_vcl_differentiates_name_value_from_name_only() {
        let command_line: Vec<String> = vec![
            "",
            "--takes_no_value",
            "--takes_value",
            "value",
            "--other_takes_no_value",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        let subject = CommandLineVcl::new(command_line.clone());

        assert_eq!(
            subject
                .vcl_args()
                .into_iter()
                .map(|v| v.name())
                .collect::<Vec<&str>>(),
            vec![
                "--takes_no_value",
                "--takes_value",
                "--other_takes_no_value"
            ]
        );
        assert_eq!(subject.args(), command_line);
    }

    #[test]
    #[should_panic(expected = "Expected option beginning with '--', not value")]
    fn command_line_vcl_panics_when_given_value_without_name() {
        let command_line: Vec<String> = vec!["", "value"]
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        CommandLineVcl::new(command_line.clone());
    }

    #[test]
    fn environment_vcl_works() {
        let _guard = EnvironmentGuard::new();
        let schema = App::new("test").arg(
            Arg::with_name("numeric-arg")
                .long("numeric-arg")
                .takes_value(true),
        );
        std::env::set_var("SUB_NUMERIC_ARG", "47");

        let subject = EnvironmentVcl::new(&schema);

        assert_eq!(
            vec![
                "".to_string(),
                "--numeric-arg".to_string(),
                "47".to_string()
            ],
            subject.args()
        );
        assert_eq!(
            vec!["--numeric-arg"],
            subject
                .vcl_args()
                .into_iter()
                .map(|v| v.name())
                .collect::<Vec<&str>>()
        );
    }

    #[test]
    fn config_file_vcl_works() {
        let home_dir = ensure_node_home_directory_exists("multi_config", "config_file_vcl_works");
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");
        {
            let mut toml_file = File::create(&file_path).unwrap();
            toml_file
                .write_all(b"numeric-arg = 47\nstring-arg = \"booga\"\nboolean-arg = true\n")
                .unwrap();
        }

        let subject = ConfigFileVcl::new(&file_path, true);

        assert_eq!(
            vec![
                "".to_string(),
                "--boolean-arg".to_string(),
                "true".to_string(),
                "--numeric-arg".to_string(),
                "47".to_string(),
                "--string-arg".to_string(),
                "booga".to_string(),
            ],
            subject.args()
        );
        assert_eq!(
            vec!["--boolean-arg", "--numeric-arg", "--string-arg"],
            subject
                .vcl_args()
                .into_iter()
                .map(|v| v.name())
                .collect::<Vec<&str>>()
        );
    }

    #[test]
    fn config_file_vcl_handles_missing_file_when_not_user_specified() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_handles_missing_file_when_not_user_specified",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");

        let subject = ConfigFileVcl::new(&file_path, false);

        assert_eq!(vec!["".to_string()], subject.args());
        assert!(subject.vcl_args().is_empty());
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

        ConfigFileVcl::new(&file_path, true);
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

        ConfigFileVcl::new(&file_path, true);
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

        ConfigFileVcl::new(&file_path, true);
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

        ConfigFileVcl::new(&file_path, true);
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

        ConfigFileVcl::new(&file_path, true);
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

        ConfigFileVcl::new(&file_path, true);
    }
}
