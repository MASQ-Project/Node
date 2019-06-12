// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::response::status::*;

#[get("/bytes/<bytes>")]
fn bytes(bytes: usize) -> Accepted<String> {
    let bytes = vec![1; bytes];
    Accepted(Some(String::from_utf8(bytes).unwrap()))
}

fn main() {
    rocket::ignite().mount("/", routes![bytes]).launch();
}
