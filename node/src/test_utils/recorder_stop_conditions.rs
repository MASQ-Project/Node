// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::test_utils::recorder::{MsgRecord, MsgRecordRef};
use std::any::TypeId;

pub enum StopConditions {
    Single(StopCondition),
    Any(Vec<StopCondition>),
    All(Vec<StopCondition>),
}

pub enum StopCondition {
    StopOnType(TypeId),
    StopOnMatch {
        exemplar: MsgRecord,
    },
    StopOnPredicate {
        predicate: Box<dyn Fn(MsgRecordRef) -> bool + Send>,
    },
}

impl StopConditions {
    pub fn resolve_stop_conditions<T: PartialEq + Send + 'static>(&mut self, msg: &T) -> bool {
        if let Some(matched) = self.inspect_immutable::<T>(msg) {
            matched
        } else {
            self.inspect_mutable::<T>(msg)
        }
    }

    fn inspect_immutable<T: PartialEq + Send + 'static>(&self, msg: &T) -> Option<bool> {
        match self {
            StopConditions::Single(stop_condition) => {
                Some(stop_condition.resolve_condition::<T>(msg))
            }
            StopConditions::Any(stop_conditions) => {
                Some(Self::resolve_any::<T>(stop_conditions, msg))
            }
            StopConditions::All(_) => None,
        }
    }

    fn inspect_mutable<T: PartialEq + Send + 'static>(&mut self, msg: &T) -> bool {
        match self {
            StopConditions::All(conditions) => {
                let indexes_to_remove =
                    conditions
                        .iter()
                        .enumerate()
                        .fold(vec![], |mut acc, (idx, condition)| {
                            let matches = condition.resolve_condition::<T>(msg);
                            if matches {
                                acc.push(idx)
                            }
                            acc
                        });

                if !indexes_to_remove.is_empty() {
                    let _ = indexes_to_remove
                        .into_iter()
                        .fold(0, |removed_counter: usize, idx| {
                            conditions.remove(idx - removed_counter);
                            removed_counter + 1
                        });
                }

                conditions.is_empty()
            }
            _ => unreachable!("something is wrong"),
        }
    }

    fn resolve_any<T: PartialEq + Send + 'static>(
        conditions: &Vec<StopCondition>,
        msg: &T,
    ) -> bool {
        conditions
            .iter()
            .any(|condition| condition.resolve_condition::<T>(msg))
    }
}

impl StopCondition {
    fn resolve_condition<T: PartialEq + Send + 'static>(&self, msg: &T) -> bool {
        match self {
            StopCondition::StopOnType(type_id) => Self::matches_stop_on_type::<T>(*type_id),
            StopCondition::StopOnMatch { exemplar } => {
                Self::matches_stop_on_match::<T>(exemplar, msg)
            }
            StopCondition::StopOnPredicate { predicate } => {
                Self::matches_stop_on_predicate(predicate.as_ref(), msg)
            }
        }
    }

    fn matches_stop_on_type<T: 'static>(expected_type_id: TypeId) -> bool {
        let msg_type_id = TypeId::of::<T>();
        msg_type_id == expected_type_id
    }

    fn matches_stop_on_match<T: PartialEq + 'static>(exemplar: MsgRecordRef, msg: &T) -> bool {
        if let Some(downcast_exemplar) = exemplar.downcast_ref::<T>() {
            return downcast_exemplar == msg;
        }
        false
    }

    fn matches_stop_on_predicate<T: Send + 'static>(
        predicate: &dyn Fn(MsgRecordRef) -> bool,
        msg: &T,
    ) -> bool {
        predicate(msg as MsgRecordRef)
    }
}

#[macro_export]
macro_rules! single_type_id {
    ($single_message: ident) => {
        StopConditions::Single(StopCondition::StopOnType(TypeId::of::<$single_message>()))
    };
}

#[macro_export]
macro_rules! multiple_type_ids{
    ($($single_message: ident),+) => {
         StopConditions::All(vec![$(StopCondition::StopOnType(TypeId::of::<$single_message>())),+])
    }
}
