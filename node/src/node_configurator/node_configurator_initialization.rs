// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::apps::app_daemon;
use crate::node_configurator::NodeConfigurator;
use crate::sub_lib::utils::make_new_multi_config;
use masq_lib::multi_config::{CommandLineVcl, MultiConfig};
use masq_lib::shared_schema::ConfiguratorError;
use crate::bootstrapper::RealUser;

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct InitializationConfig {
    pub ui_port: u16,
    pub real_user_opt: Option<RealUser>,
}

pub struct NodeConfiguratorInitializationReal;

impl NodeConfiguratorInitializationReal {
    pub fn make_multi_config_daemon_specific(
        args: &[String],
    ) -> Result<MultiConfig, ConfiguratorError> {
        make_new_multi_config(
            &app_daemon(),
            vec![Box::new(CommandLineVcl::new(args.to_vec()))],
        )
    }
}

impl NodeConfigurator<InitializationConfig> for NodeConfiguratorInitializationReal {
    fn configure(
        &self,
        multi_config: &MultiConfig,
    ) -> Result<InitializationConfig, ConfiguratorError> {
        let mut config = InitializationConfig::default();
        initialization::parse_args(multi_config, &mut config);
        println!("real user is here: {:?}", config.real_user_opt);
        Ok(config)
    }
}

mod initialization {
    use super::*;
    use clap::value_t;
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::multi_config::MultiConfig;

    pub fn parse_args(multi_config: &MultiConfig, config: &mut InitializationConfig) {
        config.ui_port = value_m!(multi_config, "ui-port", u16).unwrap_or(DEFAULT_UI_PORT);
        config.real_user_opt = value_m!(multi_config, "real-user", RealUser);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ArgsBuilder;
    use masq_lib::constants::DEFAULT_UI_PORT;
    use masq_lib::multi_config::{CommandLineVcl, VirtualCommandLine};

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let args = ArgsBuilder::new().opt("--initialization");
        let mut config = InitializationConfig::default();
        let vcls: Vec<Box<dyn VirtualCommandLine>> =
            vec![Box::new(CommandLineVcl::new(args.into()))];
        let multi_config = make_new_multi_config(&app_daemon(), vcls).unwrap();

        initialization::parse_args(&multi_config, &mut config);

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
        let multi_config = make_new_multi_config(&app_daemon(), vcls).unwrap();

        initialization::parse_args(&multi_config, &mut config);

        assert_eq!(config.ui_port, 4321);
    }
}
