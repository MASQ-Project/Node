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

    pub struct TTHCommonArgs {
        pub cryptde: &'static dyn CryptDE,
        pub payload: ClientRequestPayload_0v1,
        pub source_addr: SocketAddr,
        pub timestamp: SystemTime,
        pub is_decentralized: bool,
    }

    pub struct TTHLocalArgs<'a> {
        pub common: TTHCommonArgs,
        pub logger: &'a Logger,
        pub retire_stream_key_sub_opt: Option<&'a Recipient<StreamShutdownMsg>>,
        pub hopper_sub: &'a Recipient<IncipientCoresPackage>,
        pub dispatcher_sub: &'a Recipient<TransmitDataMsg>,
        pub accountant_sub: &'a Recipient<ReportServicesConsumedMessage>,
        pub add_return_route_sub: &'a Recipient<AddReturnRouteMessage>,
    }

    pub struct TTHMovableArgs {
        pub common_opt: Option<TTHCommonArgs>,
        pub logger: Logger,
        pub retire_stream_key_sub_opt: Option<Recipient<StreamShutdownMsg>>,
        pub hopper_sub: Recipient<IncipientCoresPackage>,
        pub dispatcher_sub: Recipient<TransmitDataMsg>,
        pub accountant_sub: Recipient<ReportServicesConsumedMessage>,
        pub add_return_route_sub: Recipient<AddReturnRouteMessage>,
    }

    impl From<TTHLocalArgs<'_>> for TTHMovableArgs {
        fn from(args: TTHLocalArgs) -> Self {
            Self {
                common_opt: Some(args.common),
                logger: args.logger.clone(),
                retire_stream_key_sub_opt: args.retire_stream_key_sub_opt.cloned(),
                hopper_sub: (*args.hopper_sub).clone(),
                dispatcher_sub: (*args.dispatcher_sub).clone(),
                accountant_sub: (*args.accountant_sub).clone(),
                add_return_route_sub: (*args.add_return_route_sub).clone(),
            }
        }
    }

    impl<'a> From<&'a mut TTHMovableArgs> for TTHLocalArgs<'a> {
        fn from(args: &'a mut TTHMovableArgs) -> TTHLocalArgs<'a> {
            Self {
                common: args.common_opt.take().expectv("common args"),
                logger: &args.logger,
                retire_stream_key_sub_opt: args.retire_stream_key_sub_opt.as_ref(),
                hopper_sub: &args.hopper_sub,
                dispatcher_sub: &args.dispatcher_sub,
                accountant_sub: &args.accountant_sub,
                add_return_route_sub: &args.add_return_route_sub,
            }
        }
    }
}
