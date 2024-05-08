use std::future::Future;
// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use masq_lib::command::StdStreams;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;

pub trait ConfiguredByPrivilege {
    fn initialize_as_privileged(
        &mut self,
        multi_config: &MultiConfig,
    ) -> Result<(), ConfiguratorError>;

    fn initialize_as_unprivileged(
        &mut self,
        multi_config: &MultiConfig,
        streams: &mut StdStreams<'_>,
    ) -> Result<(), ConfiguratorError>;
}

pub trait ConfiguredServer {
    async fn make_server_future(self) -> std::io::Result<()>;
}
