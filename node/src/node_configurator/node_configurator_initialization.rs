// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::apps::app_daemon;
use crate::node_configurator::NodeConfigurator;
use crate::sub_lib::utils::make_new_multi_config;
use masq_lib::command::StdStreams;
use masq_lib::multi_config::{CommandLineVcl, MultiConfig};
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::ExpectDecent;

#[derive(Default, Clone, PartialEq, Debug)]
pub struct InitializationConfig {
    pub ui_port: u16,
}

pub struct NodeConfiguratorInitialization {}

impl NodeConfiguratorInitialization {
    pub fn make_multi_config_for_daemon<'a: 'b, 'b>(
        args: &'a [String],
        streams: &'b mut StdStreams,
    ) -> Result<MultiConfig<'a>, ConfiguratorError> {
        make_new_multi_config(
            &app_daemon(),
            vec![Box::new(CommandLineVcl::new(args.to_vec()))],
            streams,
        )
    }
}

impl NodeConfigurator<InitializationConfig> for NodeConfiguratorInitialization {
    fn configure(
        &self,
        multi_config: &MultiConfig,
        streams: Option<&mut StdStreams>,
    ) -> Result<InitializationConfig, ConfiguratorError> {
        let mut config = InitializationConfig::default();
        initialization::parse_args(
            &multi_config,
            &mut config,
            streams.expect_decent("StdStreams"),
        );
        Ok(config)
    }
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
    use crate::sub_lib::utils::make_new_test_multi_config;
    use crate::test_utils::ArgsBuilder;
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::multi_config::{CommandLineVcl, VirtualCommandLine};
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new().opt("--initialization");
        let mut config = InitializationConfig::default();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_test_multi_config(&app_daemon(), vcls).unwrap();

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
        let multi_config = make_new_test_multi_config(&app_daemon(), vcls).unwrap();

        initialization::parse_args(
            &multi_config,
            &mut config,
            &mut FakeStreamHolder::new().streams(),
        );

        assert_eq!(config.ui_port, 4321);
    }
}
