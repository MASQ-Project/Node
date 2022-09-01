// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::proxy_server) mod local {
    use crate::sub_lib::accountant::ReportServicesConsumedMessage;
    use crate::sub_lib::cryptde::CryptDE;
    use crate::sub_lib::dispatcher::StreamShutdownMsg;
    use crate::sub_lib::hopper::IncipientCoresPackage;
    use crate::sub_lib::proxy_server::{AddReturnRouteMessage, ClientRequestPayload_0v1};
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use actix::Recipient;
    use masq_lib::logger::Logger;
    use masq_lib::utils::ExpectValue;
    use std::net::SocketAddr;
    use std::time::SystemTime;

    pub struct TTHArgsLocal<'a> {
        pub common: TTHArgsCommon,
        pub logger: &'a Logger,
        pub hopper_sub: &'a Recipient<IncipientCoresPackage>,
        pub dispatcher_sub: &'a Recipient<TransmitDataMsg>,
        pub accountant_sub: &'a Recipient<ReportServicesConsumedMessage>,
        pub add_return_route_sub: &'a Recipient<AddReturnRouteMessage>,
        pub retire_stream_key_via: Option<&'a Recipient<StreamShutdownMsg>>,
    }

    pub struct TTHArgsMovable {
        pub common_opt: Option<TTHArgsCommon>,
        pub logger: Logger,
        pub hopper_sub: Recipient<IncipientCoresPackage>,
        pub dispatcher_sub: Recipient<TransmitDataMsg>,
        pub accountant_sub: Recipient<ReportServicesConsumedMessage>,
        pub add_return_route_sub: Recipient<AddReturnRouteMessage>,
        pub retire_stream_key_via: Option<Recipient<StreamShutdownMsg>>,
    }

    pub struct TTHArgsCommon {
        pub cryptde: &'static dyn CryptDE,
        pub payload: ClientRequestPayload_0v1,
        pub source_addr: SocketAddr,
        pub timestamp: SystemTime,
    }

    impl From<TTHArgsLocal<'_>> for TTHArgsMovable {
        fn from(args: TTHArgsLocal) -> Self {
            Self {
                common_opt: Some(args.common),
                logger: args.logger.clone(),
                hopper_sub: args.hopper_sub.clone(),
                dispatcher_sub: args.dispatcher_sub.clone(),
                accountant_sub: args.accountant_sub.clone(),
                add_return_route_sub: args.add_return_route_sub.clone(),
                retire_stream_key_via: args.retire_stream_key_via.cloned(),
            }
        }
    }

    impl<'a> From<&'a mut TTHArgsMovable> for TTHArgsLocal<'a> {
        fn from(args: &'a mut TTHArgsMovable) -> TTHArgsLocal<'a> {
            Self {
                common: args.common_opt.take().expectv("common args"),
                logger: &args.logger,
                hopper_sub: &args.hopper_sub,
                dispatcher_sub: &args.dispatcher_sub,
                accountant_sub: &args.accountant_sub,
                add_return_route_sub: &args.add_return_route_sub,
                retire_stream_key_via: args.retire_stream_key_via.as_ref(),
            }
        }
    }
}
