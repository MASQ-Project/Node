// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub struct ParameterFinder {
    args: Vec<String>,
}

impl ParameterFinder {
    pub fn new(args: Vec<String>) -> ParameterFinder {
        ParameterFinder { args }
    }

    pub fn find_value_for(&self, parameter_tag: &str, usage: &str) -> Option<String> {
        match self.find_values_for(parameter_tag, usage) {
            ref list if list.is_empty() => None,
            list => Some(list.first().expect("Internal error").to_string()),
        }
    }

    pub fn find_values_for(&self, parameter_tag: &str, usage: &str) -> Vec<String> {
        self.validate(parameter_tag, usage);
        self.pairs()
            .into_iter()
            .filter(|pair| pair.0 == String::from(parameter_tag))
            .map(|pair| pair.1)
            .collect()
    }

    fn validate(&self, parameter_tag: &str, usage: &str) {
        // FIXME discuss: this implies that commandline arguments will always have a value. Kristen thinks this is OK.
        if let Some(f) = self.args.last() {
            if f == parameter_tag {
                panic!("Missing value for {}: {}", parameter_tag, usage)
            }
        }
    }

    fn pairs(&self) -> Vec<(String, String)> {
        let shifted = self.args.clone().into_iter().skip(1);
        self.args.clone().into_iter().zip(shifted).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_value_for_returns_none_if_tag_not_found() {
        let args = vec![String::from("--other-tag"), String::from("other_value")];

        let subject = ParameterFinder::new(args);

        assert_eq!(
            subject.find_value_for("--tag_not_present", "usage N/A"),
            None
        )
    }

    #[test]
    fn find_value_for_returns_arg_after_tag() {
        let args = vec![
            String::from("--other_tag"),
            String::from("other_value"),
            String::from("--tag"),
            String::from("value"),
        ];

        let subject = ParameterFinder::new(args);

        assert_eq!(
            subject.find_value_for("--tag", "usage"),
            Some(String::from("value"))
        );
    }

    #[test]
    fn find_values_for_returns_empty_list_if_tag_not_found() {
        let args = vec![String::from("--other-tag"), String::from("other_value")];
        let subject = ParameterFinder::new(args);

        let result = subject.find_values_for("--tag_not_present", "usage N/A");

        assert_eq!(result.is_empty(), true)
    }

    #[test]
    #[should_panic(expected = "Missing value for --missing_value: usage")]
    fn find_values_for_panics_with_usage_if_tag_is_the_last_arg_with_no_value() {
        let args = vec![
            String::from("--other-tag"),
            String::from("other_value"),
            String::from("--missing_value"),
        ];
        let subject = ParameterFinder::new(args);

        let _ = subject.find_values_for("--missing_value", "usage");
    }

    #[test]
    fn find_values_for_returns_arg_after_tag_multiple_times() {
        let args: Vec<String> = vec![
            "--irrelevant",
            "irrelevant",
            "--tag",
            "first_value",
            "--irrelevant",
            "irrelevant",
            "--tag",
            "second_value",
            "--tag",
            "third_value",
            "--irrelevant",
            "irrelevant",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let subject = ParameterFinder::new(args);

        let result = subject.find_values_for("--tag", "usage");

        let expected: Vec<String> = vec!["first_value", "second_value", "third_value"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(result, expected);
    }
}
