// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use masq_lib::command::StdStreams;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;
use std::marker::Send;
use tokio::prelude::Future;

pub trait ConfiguredByPrivilege: Send + Future<Item = (), Error = ()> {
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
