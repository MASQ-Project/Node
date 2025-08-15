// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::cell::RefCell;
use std::clone::Clone;
use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;
use std::time::Duration;
use std::time::Instant;

pub struct TtlHashMap<K, V>
where
    K: Hash + Clone,
{
    last_check: RefCell<Instant>,
    data: RefCell<HashMap<K, (Rc<V>, Instant)>>,
    ttl: Duration,
}

impl<K, V> TtlHashMap<K, V>
where
    K: Hash + Clone + Eq,
    V: Eq,
{
    pub fn new(ttl: Duration) -> TtlHashMap<K, V> {
        TtlHashMap {
            last_check: RefCell::new(Instant::now()),
            data: RefCell::new(HashMap::new()),
            ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn insert(&mut self, key: K, value: V) {
        self.remove_expired_entries();

        self.data
            .borrow_mut()
            .insert(key, (Rc::new(value), Instant::now()));
    }

    pub fn get(&self, key: &K) -> Option<Rc<V>> {
        self.remove_expired_entries();

        match self.data.borrow_mut().get_mut(key) {
            Some((result, instant)) => {
                *instant = Instant::now();
                Some(result.clone())
            }
            None => None,
        }
    }

    pub fn remove(&self, key: &K) -> Option<Rc<V>> {
        self.remove_expired_entries();

        match self.data.borrow_mut().remove(key) {
            Some((result, _)) => {
                Some(result)
            }
            None => None,
        }
    }

    fn remove_expired_entries(&self) {
        let now = Instant::now();

        if now.duration_since(*self.last_check.borrow()) < self.ttl {
            return;
        }
        *self.last_check.borrow_mut() = now;

        let expired: Vec<K> = {
            let data = self.data.borrow();
            data.keys()
                .filter(|key| {
                    let (_, timestamp) = data.get(key).expect("Key magically disappeared");
                    now.duration_since(*timestamp) > self.ttl
                })
                .cloned()
                .collect()
        };

        expired.iter().for_each(|key| {
            self.data.borrow_mut().remove(key);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn new_sets_ttl() {
        let subject = TtlHashMap::<u32, u32>::new(Duration::from_millis(1000));

        let result = subject.ttl;

        assert_eq!(result, Duration::from_millis(1000));
    }

    #[test]
    fn get_returns_none_for_entry_that_was_never_inserted() {
        let subject = TtlHashMap::<u32, u32>::new(Duration::from_millis(1000));

        let result = subject.get(&11u32);

        assert_eq!(result, None);
        assert_eq!(subject.ttl(), Duration::from_millis(1000));
    }

    #[test]
    fn remove_returns_none_if_no_such_entry_exists() {
        let subject = TtlHashMap::<u32, u32>::new(Duration::from_millis(1000));

        let result = subject.remove(&11u32);

        assert_eq!(result, None);
    }

    #[test]
    fn remove_returns_existing_entry_and_removes() {
        let mut subject = TtlHashMap::<u32, u32>::new(Duration::from_millis(1000));
        subject.insert(11u32, 42u32);

        let before_result = subject.remove(&11u32);
        let after_result = subject.remove(&11u32);

        assert_eq!(before_result, Some(Rc::new(42u32)));
        assert_eq!(after_result, None);
    }

    #[test]
    fn ttl_hashmap_remove_removes_expired_entry() {
        let mut subject = TtlHashMap::new(Duration::from_millis(10));
        subject.insert(42u32, "Hello");
        thread::sleep(Duration::from_millis(20));

        let result = subject.remove(&11u32); // nonexistent key

        assert_eq!(result, None);
        // Low-level get, because high-level get would remove it if .remove() didn't
        assert_eq!(subject.data.borrow().get(&42u32), None);
    }

    #[test]
    fn ttl_hashmap_does_not_remove_entry_before_it_is_expired() {
        let mut subject = TtlHashMap::new(Duration::from_millis(10));

        subject.insert(42u32, "Hello");
        subject.insert(24u32, "World");

        assert_eq!(subject.get(&42u32).unwrap().as_ref(), &"Hello");
        assert_eq!(subject.get(&24u32).unwrap().as_ref(), &"World");
        assert_eq!(subject.ttl(), Duration::from_millis(10));
    }

    #[test]
    fn ttl_hashmap_get_removes_expired_entry() {
        let mut subject = TtlHashMap::new(Duration::from_millis(10));
        subject.insert(42u32, "Hello");
        thread::sleep(Duration::from_millis(20));

        let result = subject.get(&42u32);

        assert_eq!(result, None);
    }

    #[test]
    fn ttl_hashmap_insert_removes_expired_entry() {
        let mut subject = TtlHashMap::new(Duration::from_millis(10));
        subject.insert(42u32, "Hello");
        thread::sleep(Duration::from_millis(20));

        subject.insert(24u32, "World");

        assert_eq!(subject.data.borrow().get(&42u32), None);
        assert_eq!(
            subject.data.borrow().get(&24u32).unwrap().0.as_ref(),
            &"World"
        );
    }

    #[test]
    fn ttl_hashmap_get_preserves_otherwise_expired_entry() {
        // Note: You may think that these delays are far too long for unit tests, and that you can
        // reduce them proportionally and get faster test execution. Before you do, though, be sure the
        // reduced test runs reliably on the Mac. We were seeing granularities of 200ms (that is, if you
        // order a 5ms sleep, you get 200ms) in early March 2019.
        let mut subject = TtlHashMap::new(Duration::from_millis(500));

        subject.insert(42u32, "Hello");

        let timestamp = Instant::now();
        thread::sleep(Duration::from_millis(250));
        subject
            .get(&42u32)
            .expect(time_since_msg(timestamp, 250).as_str());
        thread::sleep(Duration::from_millis(250));
        subject
            .get(&42u32)
            .expect(time_since_msg(timestamp, 500).as_str());
        thread::sleep(Duration::from_millis(250));

        assert_eq!(
            subject
                .get(&42u32)
                .expect(time_since_msg(timestamp, 750).as_str())
                .as_ref(),
            &"Hello"
        );
    }

    fn time_since_msg(timestamp: Instant, nominal: u64) -> String {
        format!(
            "Should still be there after nominal {}ms, actual {}ms",
            nominal,
            Instant::now().duration_since(timestamp).subsec_millis()
        )
    }
}
