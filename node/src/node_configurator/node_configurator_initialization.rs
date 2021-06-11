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

pub struct NodeConfiguratorInitializationReal;

impl NodeConfiguratorInitializationReal {
    pub fn make_multi_config_daemon_specific<'a: 'b, 'b>(
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

impl NodeConfigurator<InitializationConfig> for NodeConfiguratorInitializationReal {
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

#[cfg(test)]
pub mod mocks {
    use crate::node_configurator::node_configurator_initialization::InitializationConfig;
    use crate::node_configurator::NodeConfigurator;
    use crate::server_initializer::tests::extract_values_from_multi_config;
    use masq_lib::command::StdStreams;
    use masq_lib::multi_config::{MultiConfig, MultiConfigExtractedValues};
    use masq_lib::shared_schema::ConfiguratorError;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct NodeConfiguratorInitializationMock {
        demanded_values_from_multi_config: RefCell<Vec<String>>,
        configure_result: RefCell<Vec<Result<InitializationConfig, ConfiguratorError>>>,
        configure_params: RefCell<Arc<Mutex<Vec<MultiConfigExtractedValues>>>>,
    }

    impl NodeConfigurator<InitializationConfig> for NodeConfiguratorInitializationMock {
        fn configure(
            &self,
            multi_config: &MultiConfig,
            _streams: Option<&mut StdStreams>,
        ) -> Result<InitializationConfig, ConfiguratorError> {
            extract_values_from_multi_config(
                &self.demanded_values_from_multi_config,
                &self.configure_params,
                multi_config,
            );
            self.configure_result.borrow_mut().remove(0)
        }
    }

    impl NodeConfiguratorInitializationMock {
        pub fn demanded_values_from_multi_config(self, demanded_values: Vec<String>) -> Self {
            self.demanded_values_from_multi_config
                .replace(demanded_values);
            self
        }

        pub fn configure_result(
            self,
            result: Result<InitializationConfig, ConfiguratorError>,
        ) -> Self {
            self.configure_result.borrow_mut().push(result);
            self
        }

        pub fn configure_params(
            self,
            params: &Arc<Mutex<Vec<MultiConfigExtractedValues>>>,
        ) -> Self {
            self.configure_params.replace(params.clone());
            self
        }
    }
}
