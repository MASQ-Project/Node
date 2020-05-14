// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::node_configurator::{app_head, NodeConfigurator};
use clap::{App, Arg};
use lazy_static::lazy_static;
use masq_lib::command::StdStreams;
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use masq_lib::multi_config::{CommandLineVcl, MultiConfig};
use masq_lib::shared_schema::{ui_port_arg, ConfiguratorError};

lazy_static! {
    static ref UI_PORT_HELP: String = format!(
        "The port at which user interfaces will connect to the Daemon. (This is NOT the port at which \
        interfaces will connect to the Node: no one will know that until after the Node starts. \
        Best to accept the default unless you know what you're doing. Must be between {} and {}.",
        LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT
    );
}

#[derive(Default, Clone, PartialEq, Debug)]
pub struct InitializationConfig {
    pub ui_port: u16,
}

pub struct NodeConfiguratorInitialization {}

impl NodeConfigurator<InitializationConfig> for NodeConfiguratorInitialization {
    fn configure(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams,
    ) -> Result<InitializationConfig, ConfiguratorError> {
        let app = app();
        let multi_config =
            MultiConfig::try_new(&app, vec![Box::new(CommandLineVcl::new(args.clone()))])?;
        let mut config = InitializationConfig::default();
        initialization::parse_args(&multi_config, &mut config, streams);
        Ok(config)
    }
}

pub fn app() -> App<'static, 'static> {
    app_head()
        .arg(
            Arg::with_name("initialization")
                .long("initialization")
                .required(true)
                .takes_value(false)
                .help("Directs MASQ to start the Daemon that controls the Node, rather than the Node itself"),
        )
        .arg(ui_port_arg(&UI_PORT_HELP))
}

mod initialization {
    use super::*;
    use clap::value_t;
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::multi_config::MultiConfig;

    pub fn parse_args(
        multi_config: &MultiConfig,
        config: &mut InitializationConfig,
        _streams: &mut StdStreams<'_>,
    ) {
        config.ui_port = value_m!(multi_config, "ui-port", u16).unwrap_or(DEFAULT_UI_PORT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ArgsBuilder;
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::multi_config::{CommandLineVcl, MultiConfig, VirtualCommandLine};
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new().opt("--initialization");
        let mut config = InitializationConfig::default();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::try_new(&app(), vcls).unwrap();

        initialization::parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config.ui_port, DEFAULT_UI_PORT);
    }

    #[test]
    fn parse_args_creates_configuration_with_values() {
        let args = ArgsBuilder::new()
            .opt("--initialization")
            .param("--ui-port", "4321");
        let mut config = InitializationConfig::default();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = MultiConfig::try_new(&app(), vcls).unwrap();

        initialization::parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config.ui_port, 4321);
    }
}
