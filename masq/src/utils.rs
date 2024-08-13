// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[macro_export]
macro_rules! masq_short_writeln {
    ($term_interface: expr) => (
             $term_interface.writeln("").await
    );
    ( $term_interface: expr, $($arg:tt)*) => {
         {
             $term_interface.writeln(&format!($($arg)*)).await
         };
    };
}
