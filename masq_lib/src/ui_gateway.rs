// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use actix::Message;
use serde_derive::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum MessageTarget {
    ClientId(u64),
    AllExcept(u64),
    AllClients,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MessagePath {
    FireAndForget,
    Conversation(u64), // context_id
}

impl MessagePath {
    pub fn context_id(&self) -> u64 {
        match self {
            MessagePath::FireAndForget => 0,
            MessagePath::Conversation(context_id) => *context_id,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MessageBody {
    pub opcode: String,
    pub path: MessagePath,
    pub payload: Result<String, (u64, String)>, // <success payload as JSON, (error code, error message)>
}

#[derive(Message, PartialEq, Eq, Clone, Debug)]
#[rtype(result = "()")]
pub struct NodeFromUiMessage {
    pub client_id: u64,
    pub body: MessageBody,
}

#[derive(Message, PartialEq, Eq, Clone, Debug)]
#[rtype(result = "()")]
pub struct NodeToUiMessage {
    pub target: MessageTarget,
    pub body: MessageBody,
}
