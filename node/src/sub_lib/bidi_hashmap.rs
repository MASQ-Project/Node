// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::collections::HashMap;
use std::hash::Hash;

pub struct BidiHashMap<A, B>
where
    A: Hash + Clone,
    B: Hash + Clone,
{
    a_to_b: HashMap<A, B>,
    b_to_a: HashMap<B, A>,
}

impl<A, B> Default for BidiHashMap<A, B>
where
    A: Hash + Eq + Clone,
    B: Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<A, B> BidiHashMap<A, B>
where
    A: Hash + Eq + Clone,
    B: Hash + Eq + Clone,
{
    pub fn new() -> BidiHashMap<A, B> {
        BidiHashMap {
            a_to_b: HashMap::new(),
            b_to_a: HashMap::new(),
        }
    }

    pub fn insert(&mut self, a: A, b: B) {
        // TODO: Possibly return an option of a tuple in case we overwrote something
        self.a_to_b.insert(a.clone(), b.clone());
        self.b_to_a.insert(b, a);
    }

    pub fn len(&self) -> usize {
        self.a_to_b.len()
    }

    pub fn a_to_b(&self, a: &A) -> Option<B> {
        self.a_to_b.get(a).cloned()
    }

    pub fn b_to_a(&self, b: &B) -> Option<A> {
        self.b_to_a.get(b).cloned()
    }

    pub fn remove_a(&mut self, a: &A) -> Option<B> {
        self.a_to_b.remove(a).map(|b| {
            self.b_to_a.remove(&b);
            b
        })
    }

    pub fn remove_b(&mut self, b: &B) -> Option<A> {
        self.b_to_a.remove(b).map(|a| {
            self.a_to_b.remove(&a);
            a
        })
    }

    pub fn is_empty(&self) -> bool {
        self.a_to_b.is_empty() && self.b_to_a.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_insert_and_a_to_b() {
        let mut subject = BidiHashMap::new();

        subject.insert("Polly", 5);
        let result = subject.a_to_b(&"Polly");

        assert_eq!(result, Some(5));
    }

    #[test]
    fn new_insert_and_b_to_a() {
        let mut subject = BidiHashMap::new();

        subject.insert("Polly", 5);
        let result = subject.b_to_a(&5);

        assert_eq!(result, Some("Polly"));
    }

    #[test]
    fn remove_a_removing_consistent_record() {
        let mut subject = BidiHashMap::new();
        subject.insert("Polly", 5);
        subject.insert("Billy", 2);

        let result = subject.remove_a(&"Polly");

        assert_eq!(result, Some(5));
        assert_eq!(subject.a_to_b(&"Polly"), None);
        assert_eq!(subject.b_to_a(&5), None);
        assert_eq!(subject.a_to_b(&"Billy"), Some(2));
        assert_eq!(subject.b_to_a(&2), Some("Billy"));
    }

    #[test]
    fn remove_a_removing_record_with_no_a_side() {
        let mut subject = BidiHashMap::new();
        subject.b_to_a.insert(5, "Polly");

        let result = subject.remove_a(&"Polly");

        assert_eq!(result, None);
        assert_eq!(subject.a_to_b(&"Polly"), None);
        assert_eq!(subject.b_to_a(&5), Some("Polly"));
    }

    #[test]
    fn remove_b_removing_consistent_record() {
        let mut subject = BidiHashMap::new();
        subject.insert("Polly", 5);
        subject.insert("Billy", 2);

        let result = subject.remove_b(&5);

        assert_eq!(result, Some("Polly"));
        assert_eq!(subject.a_to_b(&"Polly"), None);
        assert_eq!(subject.b_to_a(&5), None);
        assert_eq!(subject.a_to_b(&"Billy"), Some(2));
        assert_eq!(subject.b_to_a(&2), Some("Billy"));
    }

    #[test]
    fn remove_b_removing_record_with_no_b_side() {
        let mut subject = BidiHashMap::new();
        subject.a_to_b.insert("Polly", 5);

        let result = subject.remove_b(&5);

        assert_eq!(result, None);
        assert_eq!(subject.b_to_a(&5), None);
        assert_eq!(subject.a_to_b(&"Polly"), Some(5));
    }

    #[test]
    fn len_with_consistent_data() {
        let mut subject = BidiHashMap::new();

        assert_eq!(subject.len(), 0);

        subject.insert("Polly", 5);

        assert_eq!(subject.len(), 1);

        subject.insert("Billy", 2);

        assert_eq!(subject.len(), 2);

        subject.remove_a(&"Polly");

        assert_eq!(subject.len(), 1);
    }

    #[test]
    fn is_empty_when_empty() {
        let subject = BidiHashMap::<u8, u8>::new();

        assert!(subject.is_empty());
    }

    #[test]
    fn is_empty_when_not_empty() {
        let mut subject = BidiHashMap::new();

        subject.insert("what", "is");

        assert!(!subject.is_empty());
    }
}
