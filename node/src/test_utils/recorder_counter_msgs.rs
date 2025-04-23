// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::test_utils::recorder_stop_conditions::{ForcedMatchable, MsgIdentification};
use actix::dev::ToEnvelope;
use actix::{Addr, Handler, Message, Recipient};
use std::any::{type_name, TypeId};
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

pub trait CounterMsgGear: Send {
    fn try_send(&self);
}

pub struct SendableCounterMsgWithRecipient<Msg>
where
    Msg: Message + Send,
    Msg::Result: Send,
{
    msg_opt: RefCell<Option<Msg>>,
    recipient: Recipient<Msg>,
}

impl<Msg> CounterMsgGear for SendableCounterMsgWithRecipient<Msg>
where
    Msg: Message + Send,
    Msg::Result: Send,
{
    fn try_send(&self) {
        let msg = self.msg_opt.take().unwrap();
        self.recipient.try_send(msg).unwrap()
    }
}

impl<Msg> SendableCounterMsgWithRecipient<Msg>
where
    Msg: Message + Send + 'static,
    Msg::Result: Send,
{
    pub fn new(msg: Msg, recipient: Recipient<Msg>) -> SendableCounterMsgWithRecipient<Msg> {
        Self {
            msg_opt: RefCell::new(Some(msg)),
            recipient,
        }
    }
}

pub struct CounterMsgSetup {
    // Leave them private
    trigger_msg_type_id: TypeId,
    condition: MsgIdentification,
    msg_gear: Box<dyn CounterMsgGear>,
}

impl CounterMsgSetup {
    pub fn new<Msg, Actor>(
        trigger_msg_type_id: TypeId,
        trigger_msg_id_method: MsgIdentification,
        counter_msg: Msg,
        counter_msg_actor_addr: &Addr<Actor>,
    ) -> Self
    where
        Msg: Message + Send + 'static,
        Msg::Result: Send,
        Actor: actix::Actor + Handler<Msg>,
        Actor::Context: ToEnvelope<Actor, Msg>,
    {
        let msg_gear = Box::new(SendableCounterMsgWithRecipient::new(
            counter_msg,
            counter_msg_actor_addr.clone().recipient(),
        ));
        Self {
            trigger_msg_type_id,
            condition: trigger_msg_id_method,
            msg_gear,
        }
    }
}

#[derive(Default)]
pub struct CounterMessages {
    msgs: HashMap<TypeId, Vec<CounterMsgSetup>>,
}

impl CounterMessages {
    pub fn search_for_msg_setup<Msg>(&mut self, msg: &Msg) -> Option<Box<dyn CounterMsgGear>>
    where
        Msg: ForcedMatchable<Msg> + 'static,
    {
        let type_id = msg.correct_msg_type_id();
        if let Some(msgs_vec) = self.msgs.get_mut(&type_id) {
            msgs_vec
                .iter_mut()
                .position(|cm_setup| cm_setup.condition.resolve_condition(msg))
                .map(|idx| {
                    let matching_counter_msg = msgs_vec.remove(idx);
                    matching_counter_msg.msg_gear
                })
        } else {
            None
        }
    }

    pub fn add_msg(&mut self, counter_msg_setup: CounterMsgSetup) {
        let type_id = counter_msg_setup.trigger_msg_type_id;
        match self.msgs.entry(type_id) {
            Entry::Occupied(mut existing) => existing.get_mut().push(counter_msg_setup),
            Entry::Vacant(vacant) => {
                vacant.insert(vec![counter_msg_setup]);
            }
        }
    }
}
