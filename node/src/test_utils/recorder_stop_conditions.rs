// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use itertools::Itertools;
use std::any::{Any, TypeId};

pub enum StopConditions {
    Any(Vec<MsgIdentification>),
    // Single message can eliminate _multiple_ ID Methods (previously stop conditions) by matching
    // on them.
    AllGreedily(Vec<MsgIdentification>),
    // Single message can eliminate _only one_ ID Method (previously stop conditions) by matching
    // on them. To remove others, a new message must be received.
    AllLazily(Vec<MsgIdentification>),
}

pub enum MsgIdentification {
    ByType(TypeId),
    ByMatch {
        exemplar: BoxedMsgExpected,
    },
    ByPredicate {
        predicate: Box<dyn Fn(RefMsgExpected) -> bool + Send>,
    },
}

pub type BoxedMsgExpected = Box<dyn Any + Send>;
pub type RefMsgExpected<'a> = &'a (dyn Any + Send);

impl StopConditions {
    pub fn resolve_stop_conditions<Msg: ForcedMatchable<Msg> + Send + 'static>(
        &mut self,
        msg: &Msg,
    ) -> bool {
        match self {
            StopConditions::Any(conditions) => Self::resolve_any::<Msg>(conditions, msg),
            StopConditions::AllGreedily(conditions) => {
                Self::resolve_all_greedily::<Msg>(conditions, msg)
            }
            StopConditions::AllLazily(conditions) => {
                Self::resolve_all_lazily::<Msg>(conditions, msg)
            }
        }
    }

    fn resolve_any<Msg: ForcedMatchable<Msg> + Send + 'static>(
        conditions: &Vec<MsgIdentification>,
        msg: &Msg,
    ) -> bool {
        conditions
            .iter()
            .any(|condition| condition.resolve_condition::<Msg>(msg))
    }

    fn resolve_all_greedily<Msg: ForcedMatchable<Msg> + Send + 'static>(
        conditions: &mut Vec<MsgIdentification>,
        msg: &Msg,
    ) -> bool {
        let indexes_to_remove = Self::indexes_of_matched_conditions(conditions, msg);
        Self::remove_matched_conditions(conditions, indexes_to_remove);
        conditions.is_empty()
    }

    fn indexes_of_matched_conditions<Msg: ForcedMatchable<Msg> + Send + 'static>(
        conditions: &[MsgIdentification],
        msg: &Msg,
    ) -> Vec<usize> {
        conditions
            .iter()
            .enumerate()
            .fold(vec![], |mut acc, (idx, condition)| {
                let matches = condition.resolve_condition::<Msg>(msg);
                if matches {
                    acc.push(idx)
                }
                acc
            })
    }

    fn resolve_all_lazily<Msg: ForcedMatchable<Msg> + Send + 'static>(
        conditions: &mut Vec<MsgIdentification>,
        msg: &Msg,
    ) -> bool {
        if let Some(idx) = conditions
            .iter()
            .position(|condition| condition.resolve_condition::<Msg>(msg))
        {
            conditions.remove(idx);
        }
        conditions.is_empty()
    }

    fn remove_matched_conditions(
        conditions: &mut Vec<MsgIdentification>,
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

impl MsgIdentification {
    pub fn resolve_condition<Msg: ForcedMatchable<Msg> + Send + 'static>(&self, msg: &Msg) -> bool {
        match self {
            MsgIdentification::ByType(type_id) => Self::matches_by_type::<Msg>(msg, *type_id),
            MsgIdentification::ByMatch { exemplar } => Self::is_identical::<Msg>(exemplar, msg),
            MsgIdentification::ByPredicate { predicate } => {
                Self::matches_by_predicate(predicate.as_ref(), msg)
            }
        }
    }

    fn matches_by_type<Msg: ForcedMatchable<Msg>>(msg: &Msg, expected_type_id: TypeId) -> bool {
        let trigger_msg_type_id = msg.trigger_msg_type_id();
        trigger_msg_type_id == expected_type_id
    }

    fn is_identical<Msg: ForcedMatchable<Msg> + 'static + Send>(
        exemplar: &BoxedMsgExpected,
        msg: &Msg,
    ) -> bool {
        if let Some(downcast_exemplar) = exemplar.downcast_ref::<Msg>() {
            return downcast_exemplar == msg;
        }
        false
    }

    fn matches_by_predicate<Msg: Send + 'static>(
        predicate: &dyn Fn(RefMsgExpected) -> bool,
        msg: &Msg,
    ) -> bool {
        predicate(msg as RefMsgExpected)
    }
}

pub trait ForcedMatchable<Message>: PartialEq + Send {
    fn trigger_msg_type_id(&self) -> TypeId;
}

pub struct PretendedMatchableWrapper<M: 'static + Send>(pub M);

impl<OuterM, InnerM> ForcedMatchable<OuterM> for PretendedMatchableWrapper<InnerM>
where
    OuterM: PartialEq,
    InnerM: Send,
{
    fn trigger_msg_type_id(&self) -> TypeId {
        TypeId::of::<InnerM>()
    }
}

impl<T: Send> PartialEq for PretendedMatchableWrapper<T> {
    fn eq(&self, _other: &Self) -> bool {
        panic!(
            r#"You requested MsgIdentification::ByMatch for message
            that does not implement PartialEq. Consider two other
            options: matching the type simply by its TypeId or using
            a predicate."#
        )
    }
}

#[macro_export]
macro_rules! match_lazily_every_type_id{
    ($($single_message: ident),+) => {
         StopConditions::AllLazily(vec![
              $(
                   crate::test_utils::recorder_stop_conditions::MsgIdentification::ByType(
                       TypeId::of::<$single_message>()
                   )
              ),+
         ])
    }
}

mod tests {
    use crate::accountant::{ResponseSkeleton, ScanError, ScanForNewPayables};
    use crate::daemon::crash_notification::CrashNotification;
    use crate::sub_lib::accountant::DetailedScanType;
    use crate::sub_lib::peer_actors::{NewPublicIp, StartMessage};
    use crate::test_utils::recorder_stop_conditions::{MsgIdentification, StopConditions};
    use masq_lib::messages::ScanType;
    use std::any::TypeId;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::vec;

    #[test]
    fn remove_matched_conditions_works_with_unsorted_indexes() {
        let mut conditions = vec![
            MsgIdentification::ByType(TypeId::of::<StartMessage>()),
            MsgIdentification::ByType(TypeId::of::<ScanForNewPayables>()),
            MsgIdentification::ByType(TypeId::of::<ScanError>()),
        ];
        let indexes = vec![2, 0];

        StopConditions::remove_matched_conditions(&mut conditions, indexes);

        assert_eq!(conditions.len(), 1);
        let type_id = if let MsgIdentification::ByType(type_id) = conditions[0] {
            type_id
        } else {
            panic!("expected ByType but got a different variant")
        };
        assert_eq!(type_id, TypeId::of::<ScanForNewPayables>())
    }

    #[test]
    fn stop_on_match_works() {
        let mut cond1 = StopConditions::AllGreedily(vec![MsgIdentification::ByMatch {
            exemplar: Box::new(StartMessage {}),
        }]);
        let mut cond2 = StopConditions::AllGreedily(vec![MsgIdentification::ByMatch {
            exemplar: Box::new(NewPublicIp {
                new_ip: IpAddr::V4(Ipv4Addr::new(1, 8, 6, 4)),
            }),
        }]);
        let mut cond3 = StopConditions::AllGreedily(vec![MsgIdentification::ByMatch {
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
        let mut cond_set = StopConditions::AllGreedily(vec![MsgIdentification::ByPredicate {
            predicate: Box::new(|msg| {
                let scan_err_msg: &ScanError = msg.downcast_ref().unwrap();
                scan_err_msg.scan_type == DetailedScanType::PendingPayables
            }),
        }]);
        let wrong_msg = ScanError {
            scan_type: DetailedScanType::NewPayables,
            response_skeleton_opt: None,
            msg: "booga".to_string(),
        };
        let good_msg = ScanError {
            scan_type: DetailedScanType::PendingPayables,
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
            MsgIdentification::ByType(TypeId::of::<CrashNotification>()),
            MsgIdentification::ByMatch {
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
            StopConditions::AllGreedily(_) => {
                panic!("stage {}: expected Any but got AllGreedily", msg_number)
            }
            StopConditions::AllLazily(_) => {
                panic!("stage {}: expected Any but got AllLazily", msg_number)
            }
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
    fn match_all_with_conditions_gradually_eliminated_greedily_until_empty() {
        let mut cond_set = StopConditions::AllGreedily(vec![
            MsgIdentification::ByPredicate {
                predicate: Box::new(|msg| {
                    if let Some(ip_msg) = msg.downcast_ref::<NewPublicIp>() {
                        ip_msg.new_ip.is_ipv4()
                    } else {
                        false
                    }
                }),
            },
            MsgIdentification::ByMatch {
                exemplar: Box::new(ScanForNewPayables {
                    response_skeleton_opt: Some(ResponseSkeleton {
                        client_id: 1234,
                        context_id: 789,
                    }),
                }),
            },
            MsgIdentification::ByType(TypeId::of::<NewPublicIp>()),
        ]);
        let tested_msg_1 = ScanForNewPayables {
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 789,
            }),
        };

        let kill_system = cond_set.resolve_stop_conditions::<ScanForNewPayables>(&tested_msg_1);

        assert_eq!(kill_system, false);
        assert_state_after_greedily_matched(1, &cond_set, |conds| {
            assert_eq!(conds.len(), 2);
            assert!(matches!(conds[0], MsgIdentification::ByPredicate { .. }));
            assert!(matches!(conds[1], MsgIdentification::ByType(_)));
        });
        let tested_msg_2 = NewPublicIp {
            new_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 4, 1)),
        };

        let kill_system = cond_set.resolve_stop_conditions::<NewPublicIp>(&tested_msg_2);

        assert_eq!(kill_system, true);
        assert_state_after_greedily_matched(2, &cond_set, |conds| assert!(conds.is_empty()))
    }

    fn assert_state_after_greedily_matched(
        stage: usize,
        cond_set: &StopConditions,
        apply_assertions: fn(&[MsgIdentification]),
    ) {
        match cond_set {
            StopConditions::AllGreedily(conds) => apply_assertions(conds),
            StopConditions::Any(_) => {
                panic!("Stage {stage}: expected StopConditions::AllGreedily, not Any")
            }
            StopConditions::AllLazily(_) => {
                panic!("Stage {stage}: expected StopConditions::AllGreedily, not AllLazily")
            }
        }
    }

    #[test]
    fn match_all_with_conditions_gradually_eliminated_lazily_until_empty() {
        let mut cond_set = StopConditions::AllLazily(vec![
            MsgIdentification::ByPredicate {
                predicate: Box::new(|msg| {
                    if let Some(ip_msg) = msg.downcast_ref::<NewPublicIp>() {
                        ip_msg.new_ip.is_ipv6()
                    } else {
                        false
                    }
                }),
            },
            MsgIdentification::ByType(TypeId::of::<NewPublicIp>()),
            MsgIdentification::ByType(TypeId::of::<NewPublicIp>()),
        ]);
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Stage one
        let tested_msg_1 = ScanForNewPayables {
            response_skeleton_opt: None,
        };

        let kill_system = cond_set.resolve_stop_conditions::<ScanForNewPayables>(&tested_msg_1);

        assert_eq!(kill_system, false);
        assert_state_after_lazily_matched(1, &cond_set, |conds| {
            assert_eq!(conds.len(), 3);
            assert!(matches!(conds[0], MsgIdentification::ByPredicate { .. }));
            assert!(matches!(conds[1], MsgIdentification::ByType(_)));
            assert!(matches!(conds[2], MsgIdentification::ByType(_)));
        });
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Stage two
        let tested_msg_2 = NewPublicIp {
            new_ip: IpAddr::V4(Ipv4Addr::new(6, 7, 8, 9)),
        };

        let kill_system = cond_set.resolve_stop_conditions::<NewPublicIp>(&tested_msg_2);

        assert_eq!(kill_system, false);
        assert_state_after_lazily_matched(2, &cond_set, |conds| {
            assert_eq!(conds.len(), 2);
            assert!(matches!(conds[0], MsgIdentification::ByPredicate { .. }));
            assert!(matches!(conds[1], MsgIdentification::ByType(_)));
        });
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Stage three
        let tested_msg_3 = NewPublicIp {
            new_ip: IpAddr::V6(Ipv6Addr::new(1, 2, 4, 1, 4, 3, 2, 1)),
        };

        let kill_system = cond_set.resolve_stop_conditions::<NewPublicIp>(&tested_msg_3);

        assert_eq!(kill_system, false);
        assert_state_after_lazily_matched(3, &cond_set, |conds| {
            assert_eq!(conds.len(), 1);
            assert!(matches!(conds[0], MsgIdentification::ByType(_)))
        });
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Stage four
        let tested_msg_4 = NewPublicIp {
            new_ip: IpAddr::V4(Ipv4Addr::new(45, 45, 45, 45)),
        };

        let kill_system = cond_set.resolve_stop_conditions::<NewPublicIp>(&tested_msg_4);

        assert_eq!(kill_system, true);
        assert_state_after_lazily_matched(4, &cond_set, |conds| {
            assert!(conds.is_empty());
        });
    }

    fn assert_state_after_lazily_matched(
        stage: usize,
        cond_set: &StopConditions,
        apply_assertions: fn(&[MsgIdentification]),
    ) {
        match &cond_set {
            StopConditions::AllLazily(conds) => apply_assertions(conds),
            StopConditions::Any(_) => {
                panic!("Stage {stage}: expected StopConditions::AllLazily, not Any")
            }
            StopConditions::AllGreedily(_) => {
                panic!("Stage {stage}: expected StopConditions::AllLazily, not AllGreedily")
            }
        }
    }
}
