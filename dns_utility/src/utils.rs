// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::sync::Arc;
use std::sync::Mutex;

pub fn get_parameters_from<T> (parameters_arc: Arc<Mutex<Vec<T>>>) -> Vec<T> where T: Clone {
    let parameters_guard = parameters_arc.lock ().unwrap ();
    let parameters_ref: &Vec<T> = parameters_guard.as_ref ();
    parameters_ref.clone ()
}
