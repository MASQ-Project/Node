// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::config_dumper::DumpConfigRunnerReal;
use crate::node_configurator::{DirsWrapperReal, NodeConfigurator};
use masq_lib::command::{Command, StdStreams};
use masq_lib::shared_schema::ConfiguratorError;

use crate::daemon::daemon_initializer::{
    DaemonInitializerReal, RecipientsFactoryReal, RerunnerReal,
};
use crate::daemon::ChannelFactoryReal;
use crate::node_configurator::node_configurator_initialization::{
    InitializationConfig, NodeConfiguratorInitializationReal,
};
use crate::server_initializer::{LoggerInitializerWrapperReal, ServerInitializerReal};

use masq_lib::utils::ExpectDecent;
#[cfg(test)]
use std::any::Any;
use std::cell::{RefCell};

pub struct DumpConfigRunnerFactoryReal;
pub struct ServerInitializerFactoryReal;
pub struct DaemonInitializerFactoryReal {
    configurator: RefCell<Option<Box<dyn NodeConfigurator<InitializationConfig>>>>,
}

impl DaemonInitializerFactoryReal {
    pub fn new(configurator: Box<dyn NodeConfigurator<InitializationConfig>>) -> Self {
        Self {
            configurator: RefCell::new(Some(configurator)),
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
    ) -> Result<i32, ConfiguratorError>;

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
        let configurator = self
            .configurator
            .borrow_mut()
            .take()
            .expect_decent("Configurator");
        let multi_config =
            NodeConfiguratorInitializationReal::make_multi_config_daemon_specific(args, streams)?;
        let initialization_config = configurator.configure(&multi_config, Some(streams))?;
        Ok(Box::new(DaemonInitializerReal::new(
            &DirsWrapperReal {},
            Box::new(LoggerInitializerWrapperReal {}),
            initialization_config,
            Box::new(ChannelFactoryReal::new()),
            Box::new(RecipientsFactoryReal::new()), //here the Daemon is born
            Box::new(RerunnerReal::new()),
        )))
    }
}

#[cfg(test)]
mod tests {
    use crate::daemon::daemon_initializer::DaemonInitializerReal;
    use crate::database::config_dumper::DumpConfigRunnerReal;
    use crate::node_configurator::node_configurator_initialization::{
        NodeConfiguratorInitializationReal,
    };
    use crate::run_modes_factories::{
        DaemonInitializerFactory, DaemonInitializerFactoryReal, DumpConfigRunnerFactory,
        DumpConfigRunnerFactoryReal, ServerInitializerFactory, ServerInitializerFactoryReal,
    };
    use crate::server_initializer::tests::convert_str_vec_slice_into_vec_of_strings;
    use crate::server_initializer::ServerInitializerReal;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::utils::find_free_port;

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
        let subject =
            DaemonInitializerFactoryReal::new(Box::new(NodeConfiguratorInitializationReal));
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
        let subject =
            DaemonInitializerFactoryReal::new(Box::new(NodeConfiguratorInitializationReal));
        let args =
            convert_str_vec_slice_into_vec_of_strings(&["program", "--wooooooo", "--jooooooo"]);
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
        todo!("get this test making a real and good job");
        let subject =
            DaemonInitializerFactoryReal::new(Box::new(NodeConfiguratorInitializationReal)); //TODO invent NodeConfiguratorMock
        let args =
            convert_str_vec_slice_into_vec_of_strings(&["program", "--wooooooo", "--jooooooo"]);
        let mut stream_holder = FakeStreamHolder::default();
        //
        // let result = subject.make(&args,&mut stream_holder.streams());
        //
        // let mut config_error = result.err().unwrap();
        // let actual_error = config_error.param_errors.remove(0);
        // assert!(config_error.is_empty());
        // assert_eq!(actual_error.parameter.as_str(),"<unknown>");
        // assert!(actual_error.reason.contains("Unfamiliar message: error: Found argument '--wooooooo'"),"{}",actual_error.reason);
    }
}

#[cfg(test)]
pub mod mocks {
    use crate::run_modes_factories::{
        DumpConfigRunner, DumpConfigRunnerFactory, ServerInitializer, ServerInitializerFactory,
    };
    use crate::server_initializer::test_utils::ServerInitializerMock;
    use masq_lib::command::StdStreams;
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
    pub struct DumpConfigRunnerMock {
        dump_config_results: RefCell<Vec<Result<i32, ConfiguratorError>>>,
        dump_config_params: RefCell<Arc<Mutex<Vec<Vec<String>>>>>,
    }

    impl DumpConfigRunner for DumpConfigRunnerMock {
        fn dump_config(
            &self,
            args: &[String],
            _streams: &mut StdStreams,
        ) -> Result<i32, ConfiguratorError> {
            self.dump_config_params
                .borrow()
                .lock()
                .unwrap()
                .push(args.to_vec());
            self.dump_config_results.borrow_mut().remove(0)
        }
    }

    impl DumpConfigRunnerMock {
        pub fn dump_config_result(self, result: Result<i32, ConfiguratorError>) -> Self {
            self.dump_config_results.borrow_mut().push(result);
            self
        }

        pub fn dump_config_params(self, params_arc: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.dump_config_params.replace(params_arc.clone());
            self
        }
    }
}
