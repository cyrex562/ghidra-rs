use super::ShortKeySet;

/// A [`ShortKeySet`] implementation that always contains all possible keys.
///
/// Used to save storage when sets are full.
///
/// Port of `ghidra.util.datastruct.FullKeySet`.
pub struct FullKeySet {
    num_keys: i16,
}

impl FullKeySet {
    /// Constructs a new `FullKeySet` containing keys `0..num_keys`.
    pub fn new(num_keys: i16) -> Self {
        Self { num_keys }
    }
}

impl ShortKeySet for FullKeySet {
    fn size(&self) -> usize {
        self.num_keys as usize
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn contains_key(&self, key: i16) -> bool {
        key >= 0 && key < self.num_keys
    }

    fn get_first(&self) -> Option<i16> {
        Some(0)
    }

    fn get_last(&self) -> Option<i16> {
        Some(self.num_keys - 1)
    }

    /// Panics if `key` is out of range `[0, num_keys)`.
    fn put(&mut self, key: i16) {
        if key < 0 || key >= self.num_keys {
            panic!("index out of bounds");
        }
    }

    /// Always panics: removing a key from a full set is not supported.
    ///
    /// Panics if `key` is out of range `[0, num_keys)`.
    fn remove(&mut self, key: i16) -> bool {
        if key < 0 || key >= self.num_keys {
            panic!("index out of bounds");
        }
        unimplemented!("remove is not supported on FullKeySet")
    }

    /// Always panics: removing all keys from a full set is not supported.
    fn remove_all(&mut self) {
        unimplemented!("remove_all is not supported on FullKeySet")
    }

    /// Panics if `key` is out of range `[0, num_keys)`.
    fn get_next(&self, key: i16) -> Option<i16> {
        if key < 0 || key >= self.num_keys {
            panic!("index out of bounds");
        }
        if key == self.num_keys - 1 {
            return None;
        }
        Some(key + 1)
    }

    /// Panics if `key` is out of range `[0, num_keys)`.
    fn get_previous(&self, key: i16) -> Option<i16> {
        if key < 0 || key >= self.num_keys {
            panic!("index out of bounds");
        }
        if key == 0 {
            return None;
        }
        Some(key - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_returns_num_keys() {
        let s = FullKeySet::new(5);
        assert_eq!(s.size(), 5);
    }

    #[test]
    fn is_empty_always_false() {
        let s = FullKeySet::new(0);
        assert!(!s.is_empty());
    }

    #[test]
    fn contains_key_within_range() {
        let s = FullKeySet::new(5);
        assert!(s.contains_key(0));
        assert!(s.contains_key(4));
        assert!(!s.contains_key(5));
        assert!(!s.contains_key(-1));
    }

    #[test]
    fn get_first_is_zero() {
        let s = FullKeySet::new(5);
        assert_eq!(s.get_first(), Some(0));
    }

    #[test]
    fn get_last_is_num_keys_minus_one() {
        let s = FullKeySet::new(5);
        assert_eq!(s.get_last(), Some(4));
    }

    #[test]
    fn put_within_range_does_not_panic() {
        let mut s = FullKeySet::new(5);
        s.put(3);
    }

    #[test]
    #[should_panic]
    fn put_out_of_range_panics() {
        let mut s = FullKeySet::new(5);
        s.put(5);
    }

    #[test]
    #[should_panic]
    fn remove_always_panics() {
        let mut s = FullKeySet::new(5);
        s.remove(3);
    }

    #[test]
    #[should_panic]
    fn remove_out_of_range_panics() {
        let mut s = FullKeySet::new(5);
        s.remove(10);
    }

    #[test]
    #[should_panic]
    fn remove_all_panics() {
        let mut s = FullKeySet::new(5);
        s.remove_all();
    }

    #[test]
    fn get_next_returns_successor() {
        let s = FullKeySet::new(5);
        assert_eq!(s.get_next(0), Some(1));
        assert_eq!(s.get_next(3), Some(4));
        assert_eq!(s.get_next(4), None);
    }

    #[test]
    #[should_panic]
    fn get_next_out_of_range_panics() {
        let s = FullKeySet::new(5);
        s.get_next(5);
    }

    #[test]
    fn get_previous_returns_predecessor() {
        let s = FullKeySet::new(5);
        assert_eq!(s.get_previous(4), Some(3));
        assert_eq!(s.get_previous(1), Some(0));
        assert_eq!(s.get_previous(0), None);
    }

    #[test]
    #[should_panic]
    fn get_previous_out_of_range_panics() {
        let s = FullKeySet::new(5);
        s.get_previous(-1);
    }
}
