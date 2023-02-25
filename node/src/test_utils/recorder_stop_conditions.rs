// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::test_utils::recorder::{MsgRecordBoxed, MsgRecordRef};
use std::any::TypeId;

pub enum StopConditions {
    Single(StopCondition),
    Any(Vec<StopCondition>),
    All(Vec<StopCondition>),
}

pub enum StopCondition {
    StopOnType(TypeId),
    StopOnMatch {
        exemplar: MsgRecordBoxed,
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

    fn resolve_any<T: PartialEq + Send + 'static>(
        conditions: &Vec<StopCondition>,
        msg: &T,
    ) -> bool {
        conditions
            .iter()
            .any(|condition| condition.resolve_condition::<T>(msg))
    }

    fn inspect_mutable<T: PartialEq + Send + 'static>(&mut self, msg: &T) -> bool {
        match self {
            StopConditions::All(conditions) => {
                let indexes_to_remove = Self::indexes_of_matched_conditions(conditions, msg);
                Self::remove_matched_conditions(conditions, indexes_to_remove);
                conditions.is_empty()
            }
            _ => unreachable!("something is wrong"),
        }
    }

    fn indexes_of_matched_conditions<T: PartialEq + Send + 'static>(
        conditions: &[StopCondition],
        msg: &T,
    ) -> Vec<usize> {
        conditions
            .iter()
            .enumerate()
            .fold(vec![], |mut acc, (idx, condition)| {
                let matches = condition.resolve_condition::<T>(msg);
                if matches {
                    acc.push(idx)
                }
                acc
            })
    }

    fn remove_matched_conditions(
        conditions: &mut Vec<StopCondition>,
        indexes_to_remove: Vec<usize>,
    ) {
        if !indexes_to_remove.is_empty() {
            let _ = indexes_to_remove
                .into_iter()
                .fold(0, |removed_counter: usize, idx| {
                    conditions.remove(idx - removed_counter);
                    removed_counter + 1
                });
        }
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

    fn matches_stop_on_match<T: PartialEq + 'static + Send>(
        exemplar: &MsgRecordBoxed,
        msg: &T,
    ) -> bool {
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

mod tests {
    use crate::accountant::{ResponseSkeleton, ScanForPayables};
    use crate::sub_lib::peer_actors::{NewPublicIp, StartMessage};
    use crate::test_utils::recorder_stop_conditions::{StopCondition, StopConditions};
    use std::any::TypeId;
    use std::net::{IpAddr, Ipv4Addr};
    use std::vec;

    #[test]
    fn stop_on_match_works() {
        let mut cond1 = StopConditions::Single(StopCondition::StopOnMatch {
            exemplar: Box::new(StartMessage {}),
        });
        let mut cond2 = StopConditions::Single(StopCondition::StopOnMatch {
            exemplar: Box::new(NewPublicIp {
                new_ip: IpAddr::V4(Ipv4Addr::new(1, 8, 6, 4)),
            }),
        });
        let mut cond3 = StopConditions::Single(StopCondition::StopOnMatch {
            exemplar: Box::new(NewPublicIp {
                new_ip: IpAddr::V4(Ipv4Addr::new(44, 2, 3, 1)),
            }),
        });
        let tested_msg = NewPublicIp {
            new_ip: IpAddr::V4(Ipv4Addr::new(44, 2, 3, 1)),
        };

        assert_eq!(
            cond1.resolve_stop_conditions::<NewPublicIp>(&tested_msg),
            false
        );
        assert_eq!(
            cond2.resolve_stop_conditions::<NewPublicIp>(&tested_msg),
            false
        );
        assert_eq!(
            cond3.resolve_stop_conditions::<NewPublicIp>(&tested_msg),
            true
        )
    }

    #[test]
    fn match_any_works() {
        todo!("complete me")
    }

    #[test]
    fn match_all_partial_conditions_sequentially_eliminated_until_full_matching() {
        let mut cond_set = StopConditions::All(vec![
            StopCondition::StopOnPredicate {
                predicate: Box::new(|msg| {
                    if let Some(ip_msg) = msg.downcast_ref::<NewPublicIp>() {
                        ip_msg.new_ip.is_ipv4()
                    } else {
                        false
                    }
                }),
            },
            StopCondition::StopOnMatch {
                exemplar: Box::new(ScanForPayables {
                    response_skeleton_opt: Some(ResponseSkeleton {
                        client_id: 1234,
                        context_id: 789,
                    }),
                }),
            },
            StopCondition::StopOnType(TypeId::of::<NewPublicIp>()),
        ]);
        let tested_msg_1 = ScanForPayables {
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 789,
            }),
        };

        let kill_system = cond_set.resolve_stop_conditions::<ScanForPayables>(&tested_msg_1);

        assert_eq!(kill_system, false);
        match &cond_set {
            StopConditions::All(conds) => {
                assert_eq!(conds.len(), 2);
                assert!(matches!(conds[0], StopCondition::StopOnPredicate { .. }));
                assert!(matches!(conds[1], StopCondition::StopOnType(_)));
            }
            StopConditions::Any(_) => panic!("Stage 1: expected StopConditions::All, not ...Any"),
            StopConditions::Single(_) => {
                panic!("Stage 1: expected StopConditions::All, not ...Single")
            }
        }
        let tested_msg_2 = NewPublicIp {
            new_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 4, 1)),
        };

        let kill_system = cond_set.resolve_stop_conditions::<NewPublicIp>(&tested_msg_2);

        assert_eq!(kill_system, true);
        match cond_set {
            StopConditions::All(conds) => {
                assert!(conds.is_empty())
            }
            StopConditions::Any(_) => panic!("Stage 2: expected StopConditions::All, not ...Any"),
            StopConditions::Single(_) => {
                panic!("Stage 2: expected StopConditions::All, not ...Single")
            }
        }
    }
}
