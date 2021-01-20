// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use igd::{search_gateway,SearchOptions};

pub fn test_igdp(){
   let gate_way = search_gateway(SearchOptions::default());
   match gate_way.expect("unwrapping failed - should not happen").get_external_ip(){
       Ok(ip) => println!("\
Summary of testing IGDP/UPnP on your device:
Success
We probably got an echo of the ip address of your router: {}; check if that address is yours.",ip),
       Err(error) => println!("\n
Summary of the test of IGDP (UPnP) on your device:
Failure
Your device probably does not operate on this protocol or
the following error occurred: {:?}", error)
   };
}



