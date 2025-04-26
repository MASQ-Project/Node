// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::test_utils::recorder_stop_conditions::{ForcedMatchable, MsgIdentification};
use actix::dev::ToEnvelope;
use actix::{Actor, Addr, Handler, Message, Recipient};
use std::any::TypeId;
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

pub struct SingleCounterMsgSetup {
    // Leave them private
    trigger_msg_type_id: TypeId,
    condition: MsgIdentification,
    // Multiple messages sent off on reaction are allowed
    // (Imagine a message handler whose execution goes about more than just one msg dispatch)
    msg_gears: Vec<Box<dyn CounterMsgGear>>,
}

impl SingleCounterMsgSetup {
    pub fn new(
        trigger_msg_type_id: TypeId,
        trigger_msg_id_method: MsgIdentification,
        counter_messages: Vec<Box<dyn CounterMsgGear>>,
    ) -> Self {
        Self {
            trigger_msg_type_id,
            condition: trigger_msg_id_method,
            msg_gears: counter_messages,
        }
    }
}

#[derive(Default)]
pub struct CounterMessages {
    msgs: HashMap<TypeId, Vec<SingleCounterMsgSetup>>,
}

impl CounterMessages {
    pub fn search_for_msg_setup<Msg>(&mut self, msg: &Msg) -> Option<Vec<Box<dyn CounterMsgGear>>>
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
                    matching_counter_msg.msg_gears
                })
        } else {
            None
        }
    }

    pub fn add_msg(&mut self, counter_msg_setup: SingleCounterMsgSetup) {
        let type_id = counter_msg_setup.trigger_msg_type_id;
        match self.msgs.entry(type_id) {
            Entry::Occupied(mut existing) => existing.get_mut().push(counter_msg_setup),
            Entry::Vacant(vacant) => {
                vacant.insert(vec![counter_msg_setup]);
            }
        }
    }
}

#[macro_export]
macro_rules! setup_for_counter_msg_triggered_via_type_id{
    ($trigger_msg_type: ty, $($owned_counter_msg: expr, $respondent_actor_addr_ref: expr),+) => {

        crate::setup_for_counter_msg_triggered_via_specific_msg_id_method!(
            $trigger_msg_type,
            MsgIdentification::ByType(TypeId::of::<$trigger_msg_type>()),
            $($owned_counter_msg, $respondent_actor_addr_ref),+
        )
    };
}

#[macro_export]
macro_rules! setup_for_counter_msg_triggered_via_specific_msg_id_method{
    ($trigger_msg_type: ty, $msg_id_method: expr, $($owned_counter_msg: expr, $respondent_actor_addr_ref: expr),+) => {
        // This macro returns a block of operations. That's why it begins with these curly brackets
        {
            let msg_gears: Vec<
                Box<dyn crate::test_utils::recorder_counter_msgs::CounterMsgGear>
            > = vec![
                // This part can be repeated as long as there are more expression pairs suplied
                $(Box::new(
                    crate::test_utils::recorder_counter_msgs::SendableCounterMsgWithRecipient::new(
                        $owned_counter_msg,
                        $respondent_actor_addr_ref.clone().recipient()
                    )
                )),+
            ];

            SingleCounterMsgSetup::new(
                TypeId::of::<$trigger_msg_type>(),
                $msg_id_method,
                msg_gears
            )
        }
    };
}
