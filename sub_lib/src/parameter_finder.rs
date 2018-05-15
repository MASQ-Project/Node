// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub struct ParameterFinder<'a> {
    args: &'a Vec<String>
}

impl<'a> ParameterFinder<'a> {
    pub fn new (args: &'a Vec<String>) -> ParameterFinder<'a> {
        ParameterFinder {args}
    }

    pub fn find_value_for(&self, parameter_tag: &str, usage: &str) -> Option<String> {
        // FIXME discuss: this implies that commandline arguments will always have a value. Kristen thinks this is OK.
        if let Some(f) = self.args.last() {
            if f == parameter_tag {
                panic!("Missing value for {}: {}", parameter_tag, usage)
            }
        }

        let shifted = self.args.iter().skip(1);
        let mut zip = self.args.iter().zip(shifted);
        match zip.find(|&(f, _)| { *f == String::from(parameter_tag) }) {
            Some((_, value)) => Some(value.clone()),
            None => None,
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn find_value_for_returns_none_if_tag_not_found() {
        let args = vec! (String::from("--other-tag"), String::from("other_value"));

        let subject = ParameterFinder::new(&args);

        assert_eq!(subject.find_value_for("--tag_not_present", "usage N/A"), None)
    }

    #[test]
    #[should_panic (expected = "Missing value for --missing_value: usage")]
    fn find_value_for_panics_with_usage_if_tag_is_the_last_arg_with_no_value() {
        let args = vec! (
            String::from("--other-tag"), String::from("other_value"),
            String::from("--missing_value")
        );

        let subject = ParameterFinder::new(&args);

        let _ = subject.find_value_for("--missing_value", "usage");
    }

    #[test]
    fn find_value_for_returns_arg_after_tag() {
        let args = vec! (
                         String::from("--other_tag"), String::from("other_value"),
                         String::from("--tag"), String::from("value"),
        );

        let subject = ParameterFinder::new(&args);

        assert_eq!(subject.find_value_for("--tag", "usage"), Some(String::from("value")));
    }
}