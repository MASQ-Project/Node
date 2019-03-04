// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub struct Limiter {
    iterations_remaining: i32,
}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter {
            iterations_remaining: -1,
        }
    }

    pub fn with_only(iterations_remaining: i32) -> Limiter {
        Limiter {
            iterations_remaining,
        }
    }

    pub fn should_continue(&mut self) -> bool {
        if self.iterations_remaining < 0 {
            true
        } else if self.iterations_remaining == 0 {
            false
        } else {
            self.iterations_remaining -= 1;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_with_only_expires() {
        let mut subject = Limiter::with_only(2);

        assert_eq!(subject.should_continue(), true);
        assert_eq!(subject.should_continue(), true);
        assert_eq!(subject.should_continue(), false);
        assert_eq!(subject.should_continue(), false);
    }

    #[test]
    fn limiter_new_does_not_expire_at_least_for_awhile() {
        let mut subject = Limiter::new();
        let before = subject.iterations_remaining;

        let result = subject.should_continue();

        let after = subject.iterations_remaining;
        assert_eq!(result, true);
        assert_eq!(before, after);
    }
}
