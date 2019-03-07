// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use sha1::Sha1;

pub struct BlockchainBridge {
    config: BlockchainBridgeConfig,
    logger: Logger,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, _msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        match self.config.consuming_private_key.as_ref() {
            Some(key) => {
                let mut hash = Sha1::new();
                hash.update(key.as_bytes()); // This is hashing the ASCII bytes of the string, not the actual bytes encoded as hex
                self.logger.debug(format!(
                    "Received BindMessage; consuming private key that hashes to {}",
                    hash.digest().to_string()
                ));
            }
            None => {
                self.logger
                    .debug("Received BindMessage; no consuming private key specified".to_string());
            }
        }
    }
}

impl BlockchainBridge {
    pub fn new(config: BlockchainBridgeConfig) -> BlockchainBridge {
        BlockchainBridge {
            config,
            logger: Logger::new("BlockchainBridge"),
        }
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
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
    use crate::test_utils::test_utils::sha1_hash;
    use actix::Addr;
    use actix::System;

    #[test]
    fn blockchain_bridge_receives_bind_message_with_consuming_private_key() {
        init_test_logging();

        let consuming_private_key =
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9".to_string();
        let subject = BlockchainBridge::new(BlockchainBridgeConfig {
            consuming_private_key: Some(consuming_private_key.clone()),
        });

        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr: Addr<BlockchainBridge> = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new()
            .exists_log_containing(&format!("DEBUG: BlockchainBridge: Received BindMessage; consuming private key that hashes to {}", sha1_hash(consuming_private_key.as_bytes())));
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_without_consuming_private_key() {
        init_test_logging();

        let subject = BlockchainBridge::new(BlockchainBridgeConfig {
            consuming_private_key: None,
        });

        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr: Addr<BlockchainBridge> = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "DEBUG: BlockchainBridge: Received BindMessage; no consuming private key specified",
        );
    }
}
