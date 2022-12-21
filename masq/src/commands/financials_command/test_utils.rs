// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub fn transpose_inputs_to_nested_tuples(
    inputs: [&str; 4],
) -> ((String, String), (String, String)) {
    (
        (inputs[0].to_string(), inputs[1].to_string()),
        (inputs[2].to_string(), inputs[3].to_string()),
    )
}
