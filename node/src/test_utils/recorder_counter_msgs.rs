// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::test_utils::recorder_stop_conditions::{ForcedMatchable, MsgIdentification};
use actix::{Message, Recipient};
use std::any::TypeId;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

// Counter-messages are a powerful tool that allows you to actively simulate communication within
// a system. They enable sending either a single message or multiple messages in response to
// a specific trigger, which is just another Actor message arriving at the Recorder.
// By trigger, we mean the moment when an incoming message is tested sequentially against collected
// identification methods and matches. Each counter-message must have its identification method
// attached when it is being prepared for storage in the Recorder.
// Counter-messages can be independently customized and targeted at different actors by
// providing their addresses, supporting complex interaction patterns. This design facilitates
// sophisticated testing scenarios by mimicking real communication flows between multiple Actors.
// The actual preparation of the Recorder needs to be carried out somewhat specifically during the
// late stage of configuring the test, when all participating Actors are already started and their
// addresses are known. The setup for counter-messages must be registered with the appropriate
// Recorder using a specially designated Actor message called `SetUpCounterMsgs`.

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

pub struct SingleTypeCounterMsgSetup {
    // Leave them private
    trigger_msg_type_id: TriggerMsgTypeId,
    trigger_msg_id_method: MsgIdentification,
    // Responding by multiple outbound messages to a single incoming (trigger) message is supported.
    // (Imitates a message handler whose execution implies a couple of message dispatches)
    msg_gears: Vec<Box<dyn CounterMsgGear>>,
}

impl SingleTypeCounterMsgSetup {
    pub fn new(
        trigger_msg_type_id: TriggerMsgTypeId,
        trigger_msg_id_method: MsgIdentification,
        msg_gears: Vec<Box<dyn CounterMsgGear>>,
    ) -> Self {
        Self {
            trigger_msg_type_id,
            trigger_msg_id_method,
            msg_gears,
        }
    }
}

pub type TriggerMsgTypeId = TypeId;

#[derive(Default)]
pub struct CounterMessages {
    msgs: HashMap<TriggerMsgTypeId, Vec<SingleTypeCounterMsgSetup>>,
}

impl CounterMessages {
    pub fn search_for_msg_gear<Msg>(
        &mut self,
        trigger_msg: &Msg,
    ) -> Option<Vec<Box<dyn CounterMsgGear>>>
    where
        Msg: ForcedMatchable<Msg> + 'static,
    {
        let type_id = trigger_msg.trigger_msg_type_id();
        if let Some(msgs_vec) = self.msgs.get_mut(&type_id) {
            msgs_vec
                .iter_mut()
                .position(|cm_setup| {
                    cm_setup
                        .trigger_msg_id_method
                        .resolve_condition(trigger_msg)
                })
                .map(|idx| msgs_vec.remove(idx).msg_gears)
        } else {
            None
        }
    }

    pub fn add_msg(&mut self, counter_msg_setup: SingleTypeCounterMsgSetup) {
        let type_id = counter_msg_setup.trigger_msg_type_id;
        match self.msgs.entry(type_id) {
            Entry::Occupied(mut existing_vec) => existing_vec.get_mut().push(counter_msg_setup),
            Entry::Vacant(vacancy) => {
                vacancy.insert(vec![counter_msg_setup]);
            }
        }
    }
}

// Note that you're not limited to triggering only one message at a time, but you can supply more
// messages to this macro, all triggered by the same type id.
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

            SingleTypeCounterMsgSetup::new(
                TypeId::of::<$trigger_msg_type>(),
                $msg_id_method,
                msg_gears
            )
        }
    };
}
