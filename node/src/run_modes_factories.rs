// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::daemon::daemon_initializer::{
    DaemonInitializerReal, RecipientsFactory, RecipientsFactoryReal, Rerunner, RerunnerReal,
};
use crate::daemon::{ChannelFactory, ChannelFactoryReal};
use crate::database::config_dumper::DumpConfigRunnerReal;
use crate::node_configurator::node_configurator_initialization::{
    InitializationConfig, NodeConfiguratorInitializationReal,
};
use crate::node_configurator::{DirsWrapper, DirsWrapperReal, NodeConfigurator};
use crate::server_initializer::{
    LoggerInitializerWrapper, LoggerInitializerWrapperReal, ServerInitializerReal,
};
use masq_lib::command::{Command, StdStreams};
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::ExpectDecent;
#[cfg(test)]
use std::any::Any;
use std::cell::RefCell;

pub struct DumpConfigRunnerFactoryReal;
pub struct ServerInitializerFactoryReal;
pub struct DaemonInitializerFactoryReal {
    configurator: RefCell<Option<Box<dyn NodeConfigurator<InitializationConfig>>>>,
    inner: RefCell<Option<ClusteredParams>>,
}

impl DaemonInitializerFactoryReal {
    fn new(
        configurator: Box<dyn NodeConfigurator<InitializationConfig>>,
        clustered_params: ClusteredParams,
    ) -> Self {
        Self {
            configurator: RefCell::new(Some(configurator)),
            inner: RefCell::new(Some(clustered_params)),
        }
    }

    //using Option for handing an owned value over to a caller because these trait objects don't have Defaults
    pub fn make_clustered_params() -> ClusteredParams {
        ClusteredParams {
            dirs_wrapper: Some(Box::new(DirsWrapperReal)),
            logger_initializer_wrapper: Some(Box::new(LoggerInitializerWrapperReal)),
            channel_factory: Some(Box::new(ChannelFactoryReal::new())),
            recipients_factory: Some(Box::new(RecipientsFactoryReal::new())),
            rerunner: Some(Box::new(RerunnerReal::new())),
        }
    }

    pub fn build() -> Self {
        DaemonInitializerFactoryReal::new(
            Box::new(NodeConfiguratorInitializationReal),
            DaemonInitializerFactoryReal::make_clustered_params(),
        )
    }

    fn expect<T>(mut value_opt: Option<T>, param: &str) -> T {
        value_opt.take().expect_decent(param)
    }

    #[cfg(test)]
    fn null_cluster_params() -> ClusteredParams {
        ClusteredParams {
            dirs_wrapper: None,
            logger_initializer_wrapper: None,
            channel_factory: None,
            recipients_factory: None,
            rerunner: None,
        }
    }
}

pub trait DumpConfigRunnerFactory {
    fn make(&self) -> Box<dyn DumpConfigRunner>;
}
pub trait ServerInitializerFactory {
    fn make(&self) -> Box<dyn ServerInitializer<Item = (), Error = ()>>;
}
pub trait DaemonInitializerFactory {
    fn make(
        &self,
        args: &[String],
        streams: &mut StdStreams,
    ) -> Result<Box<dyn DaemonInitializer>, ConfiguratorError>;
}

pub trait DumpConfigRunner {
    fn dump_config(
        &self,
        args: &[String],
        streams: &mut StdStreams,
    ) -> Result<(), ConfiguratorError>;

    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        intentionally_blank!()
    }
}

pub trait ServerInitializer: Command<ConfiguratorError> + futures::Future {
    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        intentionally_blank!()
    }
}

pub trait DaemonInitializer: Command<ConfiguratorError> {
    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        intentionally_blank!()
    }
}

impl DumpConfigRunnerFactory for DumpConfigRunnerFactoryReal {
    fn make(&self) -> Box<dyn DumpConfigRunner> {
        Box::new(DumpConfigRunnerReal)
    }
}

impl ServerInitializerFactory for ServerInitializerFactoryReal {
    fn make(&self) -> Box<dyn ServerInitializer<Item = (), Error = ()>> {
        Box::new(ServerInitializerReal::default())
    }
}

impl DaemonInitializerFactory for DaemonInitializerFactoryReal {
    fn make(
        &self,
        args: &[String],
        streams: &mut StdStreams,
    ) -> Result<Box<dyn DaemonInitializer>, ConfiguratorError> {
        let configurator = Self::expect(self.configurator.take(), "Configurator");
        let multi_config =
            NodeConfiguratorInitializationReal::make_multi_config_daemon_specific(args, streams)?;
        let initialization_config = configurator.configure(&multi_config, Some(streams))?;
        let initializer_clustered_params = Self::expect(self.inner.take(), "clustered params");
        let daemon_initializer = Box::new(DaemonInitializerReal::new(
            &*Self::expect(initializer_clustered_params.dirs_wrapper, "dirs wrapper"),
            Self::expect(
                initializer_clustered_params.logger_initializer_wrapper,
                "logger init wrapper",
            ),
            initialization_config,
            Self::expect(
                initializer_clustered_params.channel_factory,
                "channel factory",
            ),
            Self::expect(
                initializer_clustered_params.recipients_factory,
                "recipient factory",
            ), //recipient factory--here the Daemon is born
            Self::expect(initializer_clustered_params.rerunner, "rerunner"),
        ));
        Ok(daemon_initializer)
    }
}

pub struct ClusteredParams {
    dirs_wrapper: Option<Box<dyn DirsWrapper>>,
    logger_initializer_wrapper: Option<Box<dyn LoggerInitializerWrapper>>,
    channel_factory: Option<Box<dyn ChannelFactory>>,
    recipients_factory: Option<Box<dyn RecipientsFactory>>,
    rerunner: Option<Box<dyn Rerunner>>,
}

#[cfg(test)]
mod tests {
    use crate::daemon::daemon_initializer::tests::ChannelFactoryMock;
    use crate::daemon::daemon_initializer::{
        DaemonInitializerReal, RecipientsFactoryReal, RerunnerReal,
    };
    use crate::database::config_dumper::DumpConfigRunnerReal;
    use crate::node_configurator::node_configurator_initialization::mocks::NodeConfiguratorInitializationMock;
    use crate::node_configurator::node_configurator_initialization::NodeConfiguratorInitializationReal;
    use crate::run_modes_factories::{
        ClusteredParams, DaemonInitializerFactory, DaemonInitializerFactoryReal,
        DumpConfigRunnerFactory, DumpConfigRunnerFactoryReal, ServerInitializerFactory,
        ServerInitializerFactoryReal,
    };
    use crate::server_initializer::test_utils::LoggerInitializerWrapperMock;
    use crate::server_initializer::tests::{
        convert_str_vec_slice_into_vec_of_strings, make_pre_populated_mock_directory_wrapper,
    };
    use crate::server_initializer::ServerInitializerReal;
    use masq_lib::shared_schema::ConfiguratorError;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::utils::find_free_port;
    use std::sync::{Arc, Mutex};

    #[test]
    fn make_for_dump_config_runner_factory_produces_a_proper_object() {
        let subject = DumpConfigRunnerFactoryReal;
        let result = subject.make();

        let _ = result
            .as_any()
            .downcast_ref::<DumpConfigRunnerReal>()
            .unwrap();
    }

    #[test]
    fn make_for_server_initializer_factory_produces_a_proper_object() {
        let subject = ServerInitializerFactoryReal;
        let result = subject.make();

        let _ = result
            .as_any()
            .downcast_ref::<ServerInitializerReal>()
            .unwrap();
    }

    #[test]
    fn make_for_daemon_initializer_factory_labours_hard_and_produces_a_proper_object() {
        let daemon_clustered_params = ClusteredParams {
            dirs_wrapper: Some(Box::new(make_pre_populated_mock_directory_wrapper())),
            logger_initializer_wrapper: Some(Box::new(LoggerInitializerWrapperMock::new())),
            channel_factory: Some(Box::new(ChannelFactoryMock::new())),
            recipients_factory: Some(Box::new(RecipientsFactoryReal::new())),
            rerunner: Some(Box::new(RerunnerReal::new())),
        };
        let subject = DaemonInitializerFactoryReal::new(
            Box::new(NodeConfiguratorInitializationReal),
            daemon_clustered_params,
        );
        let port = find_free_port();
        let args = convert_str_vec_slice_into_vec_of_strings(&[
            "program",
            "--initialization",
            "--ui-port",
            &port.to_string(),
        ]);
        let mut stream_holder = FakeStreamHolder::default();
        let result = subject.make(&args, &mut stream_holder.streams()).unwrap();

        let _ = result
            .as_any()
            .downcast_ref::<DaemonInitializerReal>()
            .unwrap();
    }

    #[test]
    fn make_for_daemon_initializer_factory_produces_an_error_when_trying_to_pass_trough_multi_config(
    ) {
        let daemon_clustered_params = DaemonInitializerFactoryReal::null_cluster_params();
        let subject = DaemonInitializerFactoryReal::new(
            Box::new(NodeConfiguratorInitializationReal),
            daemon_clustered_params,
        );
        let args =
            convert_str_vec_slice_into_vec_of_strings(&["program", "--wooooooo", "--fooooooo"]);
        let mut stream_holder = FakeStreamHolder::default();

        let result = subject.make(&args, &mut stream_holder.streams());

        let mut config_error = result.err().unwrap();
        let actual_error = config_error.param_errors.remove(0);
        assert!(config_error.is_empty());
        assert_eq!(actual_error.parameter.as_str(), "<unknown>");
        assert!(
            actual_error
                .reason
                .contains("Unfamiliar message: error: Found argument '--wooooooo'"),
            "{}",
            actual_error.reason
        );
    }

    #[test]
    fn make_for_daemon_initializer_factory_produces_an_error_when_trying_to_pass_trough_configure()
    {
        let configure_params_arc = Arc::new(Mutex::new(vec![]));
        let daemon_clustered_params = DaemonInitializerFactoryReal::null_cluster_params();
        let subject = DaemonInitializerFactoryReal::new(
            Box::new(
                NodeConfiguratorInitializationMock::default()
                    .configure_params(&configure_params_arc)
                    .configure_result(Err(ConfiguratorError::required("parameter", "too bad")))
                    .demanded_values_from_multi_config(vec!["ui-port".to_string()]),
            ),
            daemon_clustered_params,
        );
        let args = convert_str_vec_slice_into_vec_of_strings(&["program", "--initialization"]);
        let mut stream_holder = FakeStreamHolder::default();

        let result = subject.make(&args, &mut stream_holder.streams());

        let mut config_error = result.err().unwrap();
        let actual_error = config_error.param_errors.remove(0);
        assert!(config_error.is_empty());
        assert_eq!(actual_error.parameter.as_str(), "parameter");
        assert_eq!(actual_error.reason.as_str(), "too bad");
        let mut configure_params = configure_params_arc.lock().unwrap();
        assert_eq!(
            *configure_params.remove(0).arg_matches_requested_entries,
            vec!["5333".to_string()]
        )
    }
}

#[cfg(test)]
pub mod mocks {
    use crate::run_modes_factories::{
        DaemonInitializer, DaemonInitializerFactory, DumpConfigRunner, DumpConfigRunnerFactory,
        ServerInitializer, ServerInitializerFactory,
    };
    use crate::server_initializer::test_utils::ServerInitializerMock;
    use masq_lib::command::{Command, StdStreams};
    use masq_lib::shared_schema::ConfiguratorError;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    pub struct DumpConfigRunnerFactoryMock {
        dump_config: RefCell<Box<DumpConfigRunnerMock>>,
    }

    impl DumpConfigRunnerFactoryMock {
        pub fn new(dump_config: Box<DumpConfigRunnerMock>) -> Self {
            Self {
                dump_config: RefCell::new(dump_config),
            }
        }
    }

    impl DumpConfigRunnerFactory for DumpConfigRunnerFactoryMock {
        fn make(&self) -> Box<dyn DumpConfigRunner> {
            self.dump_config.take()
        }
    }

    pub struct ServerInitializerFactoryMock {
        server_initializer: RefCell<Box<ServerInitializerMock>>,
    }

    impl ServerInitializerFactoryMock {
        pub fn new(server_initializer: Box<ServerInitializerMock>) -> Self {
            Self {
                server_initializer: RefCell::new(server_initializer),
            }
        }
    }

    impl ServerInitializerFactory for ServerInitializerFactoryMock {
        fn make(&self) -> Box<dyn ServerInitializer<Item = (), Error = ()>> {
            self.server_initializer.take()
        }
    }

    #[derive(Default)]
    pub struct DaemonInitializerFactoryMock {
        make_params: Arc<Mutex<Vec<Vec<String>>>>,
        make_result: RefCell<Vec<Result<Box<dyn DaemonInitializer>, ConfiguratorError>>>,
    }

    impl DaemonInitializerFactoryMock {
        pub fn make_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.make_params = params.clone();
            self
        }

        pub fn make_result(
            self,
            result: Result<Box<dyn DaemonInitializer>, ConfiguratorError>,
        ) -> Self {
            self.make_result.borrow_mut().push(result);
            self
        }
    }

    impl DaemonInitializerFactory for DaemonInitializerFactoryMock {
        fn make(
            &self,
            args: &[String],
            _streams: &mut StdStreams,
        ) -> Result<Box<dyn DaemonInitializer>, ConfiguratorError> {
            self.make_params.lock().unwrap().push(args.to_vec());
            self.make_result.borrow_mut().remove(0)
        }
    }

    #[derive(Default)]
    pub struct DaemonInitializerMock {
        go_params: Arc<Mutex<Vec<Vec<String>>>>,
        go_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
    }

    impl DaemonInitializerMock {
        pub fn go_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.go_params = params.clone();
            self
        }

        pub fn go_results(self, result: Result<(), ConfiguratorError>) -> Self {
            self.go_results.borrow_mut().push(result);
            self
        }
    }

    impl Command<ConfiguratorError> for DaemonInitializerMock {
        fn go(
            &mut self,
            _streams: &mut StdStreams<'_>,
            args: &[String],
        ) -> Result<(), ConfiguratorError> {
            self.go_params.lock().unwrap().push(args.to_vec());
            self.go_results.borrow_mut().remove(0)
        }
    }

    impl DaemonInitializer for DaemonInitializerMock {}

    #[derive(Default)]
    pub struct DumpConfigRunnerMock {
        dump_config_results: RefCell<Vec<Result<(), ConfiguratorError>>>,
        dump_config_params: RefCell<Arc<Mutex<Vec<Vec<String>>>>>,
    }

    impl DumpConfigRunner for DumpConfigRunnerMock {
        fn dump_config(
            &self,
            args: &[String],
            _streams: &mut StdStreams,
        ) -> Result<(), ConfiguratorError> {
            self.dump_config_params
                .borrow()
                .lock()
                .unwrap()
                .push(args.to_vec());
            self.dump_config_results.borrow_mut().remove(0)
        }
    }

    impl DumpConfigRunnerMock {
        pub fn dump_config_result(self, result: Result<(), ConfiguratorError>) -> Self {
            self.dump_config_results.borrow_mut().push(result);
            self
        }

        pub fn dump_config_params(self, params_arc: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.dump_config_params.replace(params_arc.clone());
            self
        }
    }
}
