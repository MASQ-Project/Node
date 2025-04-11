// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use itertools::Itertools;
use std::any::{Any, TypeId};

pub enum StopConditions {
    Any(Vec<StopCondition>),
    All(Vec<StopCondition>),
}

pub enum StopCondition {
    StopOnType(TypeId),
    StopOnMatch {
        exemplar: BoxedMsgExpected,
    },
    StopOnPredicate {
        predicate: Box<dyn Fn(RefMsgExpected) -> bool + Send>,
    },
}

pub type BoxedMsgExpected = Box<dyn Any + Send>;
pub type RefMsgExpected<'a> = &'a (dyn Any + Send);

impl StopConditions {
    pub fn resolve_stop_conditions<T: ForcedMatchable<T> + Send + 'static>(
        &mut self,
        msg: &T,
    ) -> bool {
        match self {
            StopConditions::Any(conditions) => Self::resolve_any::<T>(conditions, msg),
            StopConditions::All(conditions) => Self::resolve_all::<T>(conditions, msg),
        }
    }

    fn resolve_any<T: ForcedMatchable<T> + Send + 'static>(
        conditions: &Vec<StopCondition>,
        msg: &T,
    ) -> bool {
        conditions
            .iter()
            .any(|condition| condition.resolve_condition::<T>(msg))
    }

    fn resolve_all<T: ForcedMatchable<T> + Send + 'static>(
        conditions: &mut Vec<StopCondition>,
        msg: &T,
    ) -> bool {
        let indexes_to_remove = Self::indexes_of_matched_conditions(conditions, msg);
        Self::remove_matched_conditions(conditions, indexes_to_remove);
        conditions.is_empty()
    }

    fn indexes_of_matched_conditions<T: ForcedMatchable<T> + Send + 'static>(
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
            indexes_to_remove
                .into_iter()
                .sorted()
                .rev()
                .for_each(|idx| {
                    conditions.remove(idx);
                });
        }
    }
}

impl StopCondition {
    fn resolve_condition<T: ForcedMatchable<T> + Send + 'static>(&self, msg: &T) -> bool {
        match self {
            StopCondition::StopOnType(type_id) => Self::matches_stop_on_type::<T>(msg, *type_id),
            StopCondition::StopOnMatch { exemplar } => {
                Self::matches_stop_on_match::<T>(exemplar, msg)
            }
            StopCondition::StopOnPredicate { predicate } => {
                Self::matches_stop_on_predicate(predicate.as_ref(), msg)
            }
        }
    }

    fn matches_stop_on_type<T: ForcedMatchable<T>>(msg: &T, expected_type_id: TypeId) -> bool {
        let correct_msg_type_id = msg.correct_msg_type_id();
        correct_msg_type_id == expected_type_id
    }

    fn matches_stop_on_match<T: ForcedMatchable<T> + 'static + Send>(
        exemplar: &BoxedMsgExpected,
        msg: &T,
    ) -> bool {
        if let Some(downcast_exemplar) = exemplar.downcast_ref::<T>() {
            return downcast_exemplar == msg;
        }
        false
    }

    fn matches_stop_on_predicate<T: Send + 'static>(
        predicate: &dyn Fn(RefMsgExpected) -> bool,
        msg: &T,
    ) -> bool {
        predicate(msg as RefMsgExpected)
    }
}

pub trait ForcedMatchable<M>: PartialEq + Send {
    fn correct_msg_type_id(&self) -> TypeId;
}

pub struct PretendedMatchableWrapper<M: 'static + Send>(pub M);

impl<OuterM, InnerM> ForcedMatchable<OuterM> for PretendedMatchableWrapper<InnerM>
where
    OuterM: PartialEq,
    InnerM: Send,
{
    fn correct_msg_type_id(&self) -> TypeId {
        TypeId::of::<InnerM>()
    }
}

impl<T: Send> PartialEq for PretendedMatchableWrapper<T> {
    fn eq(&self, _other: &Self) -> bool {
        panic!(
            r#"You requested StopCondition::StopOnMatch for message
            that does not implement PartialEq. Consider two other
            options: matching the type simply by its TypeId or using
            a predicate."#
        )
    }
}

#[macro_export]
macro_rules! match_every_type_id{
    ($($single_message: ident),+) => {
         StopConditions::All(vec![$(StopCondition::StopOnType(TypeId::of::<$single_message>())),+])
    }
}

mod tests {
    use crate::accountant::scanners::ScanType;
    use crate::accountant::{ResponseSkeleton, ScanError, ScanForNewPayables};
    use crate::daemon::crash_notification::CrashNotification;
    use crate::sub_lib::peer_actors::{NewPublicIp, StartMessage};
    use crate::test_utils::recorder_stop_conditions::{StopCondition, StopConditions};
    use std::any::TypeId;
    use std::net::{IpAddr, Ipv4Addr};
    use std::vec;

    #[test]
    fn remove_matched_conditions_works_with_unsorted_indexes() {
        let mut conditions = vec![
            StopCondition::StopOnType(TypeId::of::<StartMessage>()),
            StopCondition::StopOnType(TypeId::of::<ScanForNewPayables>()),
            StopCondition::StopOnType(TypeId::of::<ScanError>()),
        ];
        let indexes = vec![2, 0];

        StopConditions::remove_matched_conditions(&mut conditions, indexes);

        assert_eq!(conditions.len(), 1);
        let type_id = if let StopCondition::StopOnType(type_id) = conditions[0] {
            type_id
        } else {
            panic!("expected StopOnType but got a different variant")
        };
        assert_eq!(type_id, TypeId::of::<ScanForNewPayables>())
    }

    #[test]
    fn stop_on_match_works() {
        let mut cond1 = StopConditions::All(vec![StopCondition::StopOnMatch {
            exemplar: Box::new(StartMessage {}),
        }]);
        let mut cond2 = StopConditions::All(vec![StopCondition::StopOnMatch {
            exemplar: Box::new(NewPublicIp {
                new_ip: IpAddr::V4(Ipv4Addr::new(1, 8, 6, 4)),
            }),
        }]);
        let mut cond3 = StopConditions::All(vec![StopCondition::StopOnMatch {
            exemplar: Box::new(NewPublicIp {
                new_ip: IpAddr::V4(Ipv4Addr::new(44, 2, 3, 1)),
            }),
        }]);
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
    fn stop_on_predicate_works() {
        let mut cond_set = StopConditions::All(vec![StopCondition::StopOnPredicate {
            predicate: Box::new(|msg| {
                let scan_err_msg: &ScanError = msg.downcast_ref().unwrap();
                scan_err_msg.scan_type == ScanType::PendingPayables
            }),
        }]);
        let wrong_msg = ScanError {
            scan_type: ScanType::Payables,
            response_skeleton_opt: None,
            msg: "booga".to_string(),
        };
        let good_msg = ScanError {
            scan_type: ScanType::PendingPayables,
            response_skeleton_opt: None,
            msg: "blah".to_string(),
        };

        assert_eq!(
            cond_set.resolve_stop_conditions::<ScanError>(&wrong_msg),
            false
        );
        assert_eq!(
            cond_set.resolve_stop_conditions::<ScanError>(&good_msg),
            true
        )
    }

    #[test]
    fn match_any_works_with_every_matching_condition_and_no_need_to_take_elements_out() {
        let mut cond_set = StopConditions::Any(vec![
            StopCondition::StopOnType(TypeId::of::<CrashNotification>()),
            StopCondition::StopOnMatch {
                exemplar: Box::new(StartMessage {}),
            },
        ]);
        let first_msg = ScanForNewPayables {
            response_skeleton_opt: None,
        };
        let second_msg = StartMessage {};
        let third_msg = CrashNotification {
            process_id: 12,
            exit_code: None,
            stderr: Some(String::from("booga")),
        };
        let inspect_len_of_any = |cond_set: &StopConditions, msg_number: usize| match cond_set {
            StopConditions::Any(conditions) => conditions.len(),
            StopConditions::All(_) => panic!("stage {}: expected Any but got All", msg_number),
        };

        assert_eq!(
            cond_set.resolve_stop_conditions::<ScanForNewPayables>(&first_msg),
            false
        );
        let len_after_stage_1 = inspect_len_of_any(&cond_set, 1);
        assert_eq!(len_after_stage_1, 2);
        assert_eq!(
            cond_set.resolve_stop_conditions::<StartMessage>(&second_msg),
            true
        );
        let len_after_stage_2 = inspect_len_of_any(&cond_set, 2);
        assert_eq!(len_after_stage_2, 2);
        assert_eq!(
            cond_set.resolve_stop_conditions::<CrashNotification>(&third_msg),
            true
        );
        let len_after_stage_3 = inspect_len_of_any(&cond_set, 3);
        assert_eq!(len_after_stage_3, 2);
    }

    #[test]
    fn match_all_with_conditions_gradually_eliminated_until_vector_is_emptied_and_it_is_match() {
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
                exemplar: Box::new(ScanForNewPayables {
                    response_skeleton_opt: Some(ResponseSkeleton {
                        client_id: 1234,
                        context_id: 789,
                    }),
                }),
            },
            StopCondition::StopOnType(TypeId::of::<NewPublicIp>()),
        ]);
        let tested_msg_1 = ScanForNewPayables {
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 789,
            }),
        };

        let kill_system = cond_set.resolve_stop_conditions::<ScanForNewPayables>(&tested_msg_1);

        assert_eq!(kill_system, false);
        match &cond_set {
            StopConditions::All(conds) => {
                assert_eq!(conds.len(), 2);
                assert!(matches!(conds[0], StopCondition::StopOnPredicate { .. }));
                assert!(matches!(conds[1], StopCondition::StopOnType(_)));
            }
            StopConditions::Any(_) => panic!("Stage 1: expected StopConditions::All, not ...Any"),
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
        }
    }
}
