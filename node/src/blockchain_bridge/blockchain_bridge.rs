// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Syn;

pub struct BlockchainBridge {
    logger: Logger,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, _msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug("Received BindMessage".to_string());
    }
}

impl BlockchainBridge {
    pub fn new(_config: BlockchainBridgeConfig) -> BlockchainBridge {
        BlockchainBridge {
            logger: Logger::new("BlockchainBridge"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: addr.clone().recipient::<BindMessage>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::peer_actors_builder;
    use actix::msgs;
    use actix::Addr;
    use actix::Arbiter;
    use actix::Syn;
    use actix::System;

    #[test]
    fn blockchain_bridge_receives_bind_message() {
        init_test_logging();

        let subject = BlockchainBridge::new(BlockchainBridgeConfig {});

        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr: Addr<Syn, BlockchainBridge> = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new()
            .exists_log_containing("DEBUG: BlockchainBridge: Received BindMessage");
    }
}
