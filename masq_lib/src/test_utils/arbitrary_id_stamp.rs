// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use lazy_static::lazy_static;
use std::sync::Mutex;

//The issues we are to solve might look as follows:

// 1) Our mockable objects are never Clone themselves (as it would break Rust trait object
// safeness) and therefore they cannot be captured unless you use a reference which is
// practically impossible with that mock strategy we use,
// 2) You can get only very limited information from downcasting: you can inspect the guts, yes,
// but it can hardly ever answer your question if the object you're looking at is the same which
// you've pasted in before at the other end.
// 3) Using raw pointers to link the real memory address to your objects does not lead to good
// results in all cases (It was found confusing and hard to be done correctly or even impossible
// to implement especially for references pointing to a dereferenced Box that was originally
// supplied as an owned argument into the testing environment at the beginning, or we can
// suspect the memory link already broken because of moves of the owned boxed instance
// around the subjected code)

// Advice is given here to use the convenient macros provided further in this module. Their easy
// implementation should spare some work for you.

// Note for future maintainers:
// Since trait objects cannot be Cloned, when you find an arbitrary ID on an object, you
// know that that ID must have been set on that specific object, and not on some other object
// from which this object was Cloned.

lazy_static! {
    pub static ref ARBITRARY_ID_STAMP_SEQUENCER: Mutex<MutexIncrementInset> =
        Mutex::new(MutexIncrementInset(0));
}

pub struct MutexIncrementInset(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArbitraryIdStamp {
    id: usize,
}

impl ArbitraryIdStamp {
    pub fn new() -> Self {
        ArbitraryIdStamp {
            id: {
                let mut access = ARBITRARY_ID_STAMP_SEQUENCER.lock().unwrap();
                access.0 += 1;
                access.0
            },
        }
    }
}

// To be added together with other methods in your trait
#[macro_export]
macro_rules! arbitrary_id_stamp_in_trait {
    () => {
        #[cfg(test)]
        fn arbitrary_id_stamp(&self) -> ArbitraryIdStamp {
            intentionally_blank!()
        }
    };
}

// The following macros might be handy but your mock object must contain this field:
//
///  struct SomeMock{
///     ...
///     arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
///     ...
///  }
//
// Refcell is omitted because ArbitraryIdStamp is Copy

#[macro_export]
macro_rules! arbitrary_id_stamp_in_trait_impl {
    () => {
        fn arbitrary_id_stamp(&self) -> ArbitraryIdStamp {
            // If missing, it might just mean the current test isn't asking for the id.
            // Preventing unnecessary writing more code in tests, this puts in a sentinel
            // with a new unique ID which is certainly not looked for in any of those
            // running tests.
            self.arbitrary_id_stamp_opt
                .unwrap_or(ArbitraryIdStamp::new())
        }
    };
}

#[macro_export]
macro_rules! set_arbitrary_id_stamp_in_mock_impl {
    () => {
        pub fn set_arbitrary_id_stamp(mut self, id_stamp: ArbitraryIdStamp) -> Self {
            self.arbitrary_id_stamp_opt.replace(id_stamp);
            self
        }
    };
}

#[cfg(test)]
mod example {
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Demonstration of implementation through made up code structures
    // Showed by a test also placed in the test section of this file

    // This is the trait object that requires some specific identification - the id stamp
    // is going to help there
    use super::*;
    use crate::test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use std::cell::RefCell;
    use std::sync::Arc;

    pub(in crate::test_utils) trait FirstTrait {
        fn whatever_method(&self) -> String;
        arbitrary_id_stamp_in_trait!();
    }

    struct FirstTraitReal {}

    impl FirstTrait for FirstTraitReal {
        fn whatever_method(&self) -> String {
            unimplemented!("example-irrelevant")
        }
    }

    #[derive(Default)]
    pub(in crate::test_utils) struct FirstTraitMock {
        #[allow(dead_code)]
        whatever_method_results: RefCell<Vec<String>>,
        arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
    }

    impl FirstTrait for FirstTraitMock {
        fn whatever_method(&self) -> String {
            unimplemented!("example-irrelevant")
        }
        arbitrary_id_stamp_in_trait_impl!();
    }

    impl FirstTraitMock {
        set_arbitrary_id_stamp_in_mock_impl!();
    }

    // We don't need an arbitrary_id in a trait if one of these things is true:

    // Objects of that trait have some native field about them that can be set to
    // different values so that we can distinguish different instances in an assertion.
    // There are no tests involving objects of that trait where instances are passed
    // as parameters to a mock and need to be asserted on as part of a ..._params_arc
    // collection.

    // This second criterion may change; therefore a trait may start out without any
    // arbitrary_id, and then at a later time collect one because of changes
    // elsewhere in the system.

    pub(in crate::test_utils) trait SecondTrait {
        fn method_with_trait_obj_arg(&self, trait_object_arg: &dyn FirstTrait) -> u16;
    }

    pub(in crate::test_utils) struct SecondTraitReal {}

    impl SecondTrait for SecondTraitReal {
        fn method_with_trait_obj_arg(&self, _trait_object_arg: &dyn FirstTrait) -> u16 {
            unimplemented!("example-irrelevant")
        }
    }

    #[derive(Default)]
    pub(in crate::test_utils) struct SecondTraitMock {
        method_with_trait_obj_arg_params: Arc<Mutex<Vec<ArbitraryIdStamp>>>,
        method_with_trait_obj_arg_results: RefCell<Vec<u16>>,
    }

    impl SecondTrait for SecondTraitMock {
        fn method_with_trait_obj_arg(&self, trait_object_arg: &dyn FirstTrait) -> u16 {
            self.method_with_trait_obj_arg_params
                .lock()
                .unwrap()
                .push(trait_object_arg.arbitrary_id_stamp());
            self.method_with_trait_obj_arg_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl SecondTraitMock {
        pub fn method_with_trait_obj_arg_params(
            mut self,
            params: &Arc<Mutex<Vec<ArbitraryIdStamp>>>,
        ) -> Self {
            self.method_with_trait_obj_arg_params = params.clone();
            self
        }

        pub fn method_with_trait_obj_arg_result(self, result: u16) -> Self {
            self.method_with_trait_obj_arg_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    pub(in crate::test_utils) struct TestSubject {
        pub some_doer: Box<dyn SecondTrait>,
    }

    impl TestSubject {
        pub fn new() -> Self {
            Self {
                some_doer: Box::new(SecondTraitReal {}),
            }
        }

        pub fn tested_function(&self, outer_object: &dyn FirstTrait) -> u16 {
            //some extra functionality might be here...

            let num = self.some_doer.method_with_trait_obj_arg(outer_object);

            //...and also here

            num
        }
    }

    #[test]
    fn demonstration_of_the_use_of_arbitrary_id_stamp() {
        let method_with_trait_obj_arg_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = TestSubject::new();
        let doer_mock = SecondTraitMock::default()
            .method_with_trait_obj_arg_params(&method_with_trait_obj_arg_params_arc)
            .method_with_trait_obj_arg_result(123);
        subject.some_doer = Box::new(doer_mock);
        let arbitrary_id = ArbitraryIdStamp::new();
        let outer_parameter = FirstTraitMock::default().set_arbitrary_id_stamp(arbitrary_id);

        let result = subject.tested_function(&outer_parameter);

        assert_eq!(result, 123);
        let method_with_trait_obj_arg_params = method_with_trait_obj_arg_params_arc.lock().unwrap();
        // This assertion proves that the same trait object as which we supplied at the beginning interacted with the method
        // 'method_with_trait_obj_arg_result' inside 'tested_function'
        assert_eq!(*method_with_trait_obj_arg_params, vec![arbitrary_id])

        // Remarkable notes:
        // Arbitrary IDs are most helpful in black-box testing where the only assertions that can
        // be made involve verifying that an object that comes out of the black box at some point is
        // exactly the same object that went into the black box at some other point, when the object
        // itself does not otherwise provide enough identifying information to make the assertion.
    }
}
