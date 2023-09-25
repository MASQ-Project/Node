// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::TypeId;
use std::mem;
use std::mem::{transmute, transmute_copy};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Obfuscated {
    type_id: TypeId,
    bytes: Vec<u8>
}

impl Obfuscated {
    pub fn obfuscate_data<D: 'static>(data: D) -> Obfuscated {
        // let bytes_length = mem::size_of_val(&data);
        // let array = vec![0,bytes_length].as_slice().
        let bytes = unsafe {
            transmute_copy::<D, Vec<u8>>(&data)
        };
        Obfuscated {
            type_id: TypeId::of::<D>(),
            bytes: bytes.to_vec()
        }
    }

    pub fn expose_data<D: 'static>(self) -> D{
        if self.type_id != TypeId::of::<D>(){
            panic!("Forbidden! You're trying to interpret obfuscated type A as type B")
        }
        unsafe {transmute_copy::<Vec<u8>, D>(&self.bytes)}
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscation_works() {
        let data = vec!["I'm fearing of losing my entire identity".to_string()];

        let obfuscated_data = Obfuscated::obfuscate_data(data.clone());
        let fenix_data: Vec<String> = obfuscated_data.expose_data();

        assert_eq!(data, fenix_data)
    }

    // #[test]
    // #[should_panic(expected="Forbidden! The two types have to have the same memory size, not  ")]
    // fn obfuscation_between_two_types_of_different_sizes_isn_not_allowed(){
    //     let short_guy = 5_u8;
    //     let long_guy = 32_u8;
    //
    //     Obfuscated::obfuscate_data(long_guy)
    // }

    #[test]
    #[should_panic(expected="Forbidden! You're trying to interpret obfuscated type A as type B")]
    fn obfuscation_attempt_to_reinterpret_to_wrong_type() {
        let data = vec![0_u64];
        let obfuscated_data = Obfuscated::obfuscate_data(data.clone());
        let _: Vec<u128> = obfuscated_data.expose_data();
    }


}
