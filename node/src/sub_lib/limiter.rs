// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::cmp::Ordering;

pub struct Limiter {
    iterations_remaining: i32,
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
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
        match self.iterations_remaining.cmp(&0) {
            Ordering::Less => true,
            Ordering::Equal => false,
            Ordering::Greater => {
                self.iterations_remaining -= 1;
                true
            }
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
