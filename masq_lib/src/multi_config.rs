// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::shared_schema::{ConfiguratorError, ParamError};
#[allow(unused_imports)]
use clap::{value_t, values_t};
use clap::{App, ArgMatches};
use regex::Regex;
use serde::export::Formatter;
use std::collections::HashSet;
use std::fmt::{Debug, Display};
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
    content: Box<dyn VirtualCommandLine>,
}

impl<'a> Debug for MultiConfig<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let representation = self
            .content
            .vcl_args()
            .into_iter()
            .map(|vcl_arg| {
                let strings = vcl_arg.to_args();
                if strings.len() == 1 {
                    strings[0].clone()
                } else {
                    format!("{} {}", strings[0], strings[1])
                }
            })
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{{{}}}", representation)
    }
}

impl<'a> MultiConfig<'a> {
    /// Create a new MultiConfig that can be passed into the value_m! and values_m! macros, containing
    /// several VirtualCommandLine objects in increasing priority order. That is, values found in
    /// VirtualCommandLine objects placed later in the list will override values found in
    /// VirtualCommandLine objects placed earlier.
    pub fn try_new(
        schema: &App<'a, 'a>,
        vcls: Vec<Box<dyn VirtualCommandLine>>,
    ) -> Result<MultiConfig<'a>, ConfiguratorError> {
        let initial: Box<dyn VirtualCommandLine> =
            Box::new(CommandLineVcl::new(vec![String::new()]));
        let merged = vcls
            .into_iter()
            .fold(initial, |so_far, vcl| merge(so_far, vcl));
        let arg_matches = match schema
            .clone()
            .get_matches_from_safe(merged.args().into_iter())
        {
            Ok(matches) => matches,
            Err(e)
                if (e.kind == clap::ErrorKind::HelpDisplayed)
                    || (e.kind == clap::ErrorKind::VersionDisplayed) =>
            {
                e.exit()
            }
            Err(e) => return Err(Self::make_configurator_error(e)),
        };
        Ok(MultiConfig {
            arg_matches,
            content: merged,
        })
    }

    pub fn arg_matches(&'a self) -> &ArgMatches<'a> {
        &self.arg_matches
    }

    fn make_configurator_error(e: clap::Error) -> ConfiguratorError {
        let invalid_value_regex =
            Regex::new("Invalid value for.*'--(.*?) <.*? (.*)$").expect("Bad regex");
        if let Some(captures) = invalid_value_regex.captures(&e.message) {
            let name = &captures[1];
            let message = format!("Invalid value: {}", &captures[2]);
            return ConfiguratorError::required(name, &message);
        }
        if e.message
            .contains("The following required arguments were not provided:")
        {
            let mut remaining_message = match e.message.find("USAGE:") {
                Some(idx) => e.message[0..idx].to_string(),
                None => e.message.to_string(),
            };
            let required_value_regex = Regex::new("--(.*?) ").expect("Bad regex");
            let mut requireds: Vec<ParamError> = vec![];
            while let Some(captures) = required_value_regex.captures(&remaining_message) {
                requireds.push(ParamError::new(
                    &captures[1],
                    "ParamError parameter not provided",
                ));
                match remaining_message.find(&captures[1]) {
                    Some(idx) => remaining_message = remaining_message[idx..].to_string(),
                    None => remaining_message = "".to_string(),
                }
            }
            return ConfiguratorError::new(requireds);
        }
        ConfiguratorError::required("<unknown>", &format!("Unfamiliar message: {}", e.message))
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

impl Debug for dyn VirtualCommandLine {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.args())
    }
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

#[derive(Debug)]
pub enum ConfigFileVclError {
    OpenError(PathBuf, std::io::Error),
    CorruptUtf8(PathBuf),
    Unreadable(PathBuf, std::io::Error),
    CorruptToml(PathBuf, toml::de::Error),
    InvalidConfig(PathBuf),
}

impl Display for ConfigFileVclError {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigFileVclError::OpenError(path, error) => writeln!(fmt, "Configuration file at {:?} could not be opened: {}", path, error),
            ConfigFileVclError::CorruptUtf8 (path) => writeln!(fmt, "Configuration file at {:?} is corrupted: contains data that cannot be interpreted as UTF-8", path),
            ConfigFileVclError::Unreadable(path, error) => writeln!(fmt, "Configuration file at {:?} could not be read: {}", path, error),
            ConfigFileVclError::CorruptToml (path, error) => writeln!(fmt, "Configuration file at {:?} has bad TOML syntax: {}", path, error),
            ConfigFileVclError::InvalidConfig (path) => writeln!(fmt, "Configuration file at {:?} contains unsupported Datetime or non-scalar configuration values", path),
        }
    }
}

impl ConfigFileVcl {
    pub fn new(
        file_path: &PathBuf,
        user_specified: bool,
    ) -> Result<ConfigFileVcl, ConfigFileVclError> {
        let mut file: File = match File::open(file_path) {
            Err(e) => {
                if user_specified {
                    return Err(ConfigFileVclError::OpenError(file_path.clone(), e));
                } else {
                    return Ok(ConfigFileVcl { vcl_args: vec![] });
                }
            }
            Ok(file) => file,
        };
        let mut contents = String::new();
        match file.read_to_string(&mut contents) {
            Err(ref e) if e.kind() == ErrorKind::InvalidData => {
                return Err(ConfigFileVclError::CorruptUtf8(file_path.clone()))
            }
            Err(e) => return Err(ConfigFileVclError::Unreadable(file_path.clone(), e)),
            Ok(_) => (),
        };
        let table: Table = match toml::de::from_str(&contents) {
            Err(e) => return Err(ConfigFileVclError::CorruptToml(file_path.clone(), e)),
            Ok(table) => table,
        };
        let vcl_args_and_errs: Vec<Result<Box<dyn VclArg>, ConfigFileVclError>> = table
            .keys()
            .map(|key| {
                let name = format!("--{}", key);
                let value = match table.get(key).expect("value disappeared") {
                    Value::Table(_) => Err(ConfigFileVclError::InvalidConfig(file_path.clone())),
                    Value::Array(_) => Err(ConfigFileVclError::InvalidConfig(file_path.clone())),
                    Value::Datetime(_) => Err(ConfigFileVclError::InvalidConfig(file_path.clone())),
                    Value::String(v) => Ok(v.as_str().to_string()),
                    v => Ok(v.to_string()),
                };
                match value {
                    Err(e) => Err(e),
                    Ok(s) => {
                        let v: Box<dyn VclArg> = Box::new(NameValueVclArg::new(&name, &s));
                        Ok(v)
                    }
                }
            })
            .collect();
        if vcl_args_and_errs.iter().any(|v| v.is_err()) {
            return Err(ConfigFileVclError::InvalidConfig(file_path.clone()));
        }
        let vcl_args = vcl_args_and_errs
            .into_iter()
            .map(|result| result.expect("Error appeared"))
            .collect();

        Ok(ConfigFileVcl { vcl_args })
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
    fn make_configurator_error_handles_unfamiliar_message() {
        let result = MultiConfig::make_configurator_error(clap::Error {
            message: "unfamiliar".to_string(),
            kind: clap::ErrorKind::InvalidValue,
            info: None,
        });

        assert_eq!(
            result,
            ConfiguratorError::required("<unknown>", "Unfamiliar message: unfamiliar")
        )
    }

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

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
        let subject = MultiConfig::try_new(&schema, vcls).unwrap();

        let result = subject.arg_matches();

        assert!(result.is_present("nonvalued"));
    }

    #[test]
    fn clap_match_error_produces_panic() {
        let schema = App::new("test")
            .arg(
                Arg::with_name("numeric-arg")
                    .long("numeric-arg")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("another-arg")
                    .long("another-arg")
                    .takes_value(true)
                    .required(true),
            );
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(vec![String::new()]))];

        let result = MultiConfig::try_new(&schema, vcls).err().unwrap();

        let expected =
            ConfiguratorError::required("another-arg", "ParamError parameter not provided")
                .another_required("numeric-arg", "ParamError parameter not provided");
        assert_eq!(result, expected);
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

    #[test] // TODO: Is it this one that segfaults on the Mac in Actions
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

        let subject = ConfigFileVcl::new(&file_path, true).unwrap();

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

        let subject = ConfigFileVcl::new(&file_path, false).unwrap();

        assert_eq!(vec!["".to_string()], subject.args());
        assert!(subject.vcl_args().is_empty());
    }

    #[test]
    fn config_file_vcl_complains_about_missing_file_when_user_specified() {
        let home_dir = ensure_node_home_directory_exists(
            "multi_config",
            "config_file_vcl_panics_about_missing_file_when_user_specified",
        );
        let mut file_path = home_dir.clone();
        file_path.push("config.toml");

        let result = ConfigFileVcl::new(&file_path, true).err().unwrap();
        assert_eq!(
            result.to_string().contains("could not be opened: "),
            true,
            "{}",
            result.to_string()
        )
    }

    #[test]
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

        let result = ConfigFileVcl::new(&file_path, true).err().unwrap();
        assert_eq!(
            result
                .to_string()
                .contains("is corrupted: contains data that cannot be interpreted as UTF-8"),
            true
        )
    }

    #[test]
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

        let result = ConfigFileVcl::new(&file_path, true).err().unwrap();
        assert_eq!(
            result.to_string().contains(
                "has bad TOML syntax: expected a table key, found a right bracket at line 1"
            ),
            true
        )
    }

    #[test]
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

        let result = ConfigFileVcl::new(&file_path, true).err().unwrap();
        assert_eq!(
            result
                .to_string()
                .contains("contains unsupported Datetime or non-scalar configuration values"),
            true
        )
    }

    #[test]
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

        let result = ConfigFileVcl::new(&file_path, true).err().unwrap();
        assert_eq!(
            result
                .to_string()
                .contains("contains unsupported Datetime or non-scalar configuration values"),
            true
        )
    }

    #[test]
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

        let result = ConfigFileVcl::new(&file_path, true).err().unwrap();
        assert_eq!(
            result
                .to_string()
                .contains("contains unsupported Datetime or non-scalar configuration values"),
            true
        )
    }
}
