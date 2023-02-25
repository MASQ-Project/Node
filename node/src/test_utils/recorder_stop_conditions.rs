// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use itertools::Either;
use log::log_enabled;
use std::any::TypeId;

pub enum StopConditions<T> {
    StopOnType(TypeId),
    StopOnMatch {
        exemplar: T,
    },
    StopOnPredicate {
        predicate: Box<dyn Fn(T) -> (bool, T) + Send>,
    },
    StopOnAny(Vec<StopConditions<T>>),
    StopOnAll(Vec<StopConditions<T>>),
}

impl<T: PartialEq> StopConditions<T> {
    pub fn resolve_stop_conditions(&mut self, msg: &T) -> bool {
        if let Some(matched) =
            self.resolve_immutable(msg, |conditions, msg| Self::resolve_any(conditions, msg))
        {
            matched
        } else {
            self.resolve_mutable(msg)
        }
    }

    fn resolve_immutable(
        &self,
        msg: &T,
        anny_fn: fn(&Vec<StopConditions<T>>, &T) -> bool,
    ) -> Option<bool> {
        match self {
            StopConditions::StopOnType(type_id) => Some(Self::matches_stop_on_type(*type_id)),
            StopConditions::StopOnMatch { exemplar } => {
                Some(Self::matches_stop_on_match(exemplar, msg))
            }
            StopConditions::StopOnPredicate { predicate } => {
                Some(Self::matches_stop_on_predicate(&*predicate, msg))
            }
            StopConditions::StopOnAny(stop_conditions) => Some(anny_fn(stop_conditions, msg)),
            StopConditions::StopOnAll(stop_conditions) => None,
        }
    }

    fn resolve_mutable(&mut self, msg: &T) -> bool {
        match self {
            StopConditions::StopOnAll(conditions) => {
                let indexes_to_remove =
                    conditions
                        .iter()
                        .enumerate()
                        .fold(vec![], |mut acc, (idx, condition)| {
                            let matches = if let Some(bool) = condition
                                .resolve_immutable(msg, |_, _| Self::nested_any_or_all_panic())
                            {
                                bool
                            } else {
                                Self::nested_any_or_all_panic()
                            };
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
        };
        todo!()
    }

    fn resolve_any(conditions: &Vec<StopConditions<T>>, msg: &T) -> bool {
        conditions.iter().any(|condition| {
            condition
                .resolve_immutable(msg, |_, _| Self::nested_any_or_all_panic())
                .unwrap()
        })
    }

    fn matches_stop_on_type(expected_type_id: TypeId) -> bool {
        let msg_type_id = TypeId::of::<T>();
        msg_type_id == expected_type_id
    }

    fn matches_stop_on_match(exemplar: &T, msg: &T) -> bool {
        exemplar == msg
    }

    fn matches_stop_on_predicate(predicate: &dyn Fn(&T) -> bool, msg: &T) -> bool {
        predicate(msg)
    }

    fn nested_any_or_all_panic() -> ! {
        panic!("Do not use nested StopOnAny or StopOnAll! The same idea can be expressed within just a single layer")
    }
}
