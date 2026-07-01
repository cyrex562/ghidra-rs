use crate::feature::bsim::query::description::RowKey;
use std::cmp::Ordering;

/// Mirrors `ghidra.features.bsim.query.client.RowKeySQL`.
///
/// A concrete implementation of RowKey backed by a 64-bit unique ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RowKeySQL {
    id: i64,
}

impl RowKeySQL {
    pub fn new(id: i64) -> Self {
        Self { id }
    }
}

impl PartialOrd for RowKeySQL {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RowKeySQL {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl RowKey for RowKeySQL {
    fn get_long(&self) -> i64 {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_new_stores_id() {
        let key = RowKeySQL::new(42);
        assert_eq!(key.get_long(), 42);
    }

    #[test]
    fn test_new_with_negative_id() {
        let key = RowKeySQL::new(-1);
        assert_eq!(key.get_long(), -1);
    }

    #[test]
    fn test_new_with_zero() {
        let key = RowKeySQL::new(0);
        assert_eq!(key.get_long(), 0);
    }

    #[test]
    fn test_new_with_min_max_id() {
        let min_key = RowKeySQL::new(i64::MIN);
        let max_key = RowKeySQL::new(i64::MAX);
        assert_eq!(min_key.get_long(), i64::MIN);
        assert_eq!(max_key.get_long(), i64::MAX);
    }

    #[test]
    fn test_cmp_less() {
        let a = RowKeySQL::new(1);
        let b = RowKeySQL::new(2);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert!(a < b);
    }

    #[test]
    fn test_cmp_greater() {
        let a = RowKeySQL::new(2);
        let b = RowKeySQL::new(1);
        assert_eq!(a.cmp(&b), Ordering::Greater);
        assert!(a > b);
    }

    #[test]
    fn test_cmp_equal() {
        let a = RowKeySQL::new(5);
        let b = RowKeySQL::new(5);
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_eq!(a, b);
    }

    #[test]
    fn test_equals() {
        let a = RowKeySQL::new(42);
        let b = RowKeySQL::new(42);
        assert_eq!(a, b);
    }

    #[test]
    fn test_not_equals() {
        let a = RowKeySQL::new(1);
        let b = RowKeySQL::new(2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_consistency() {
        let a = RowKeySQL::new(42);
        let b = RowKeySQL::new(42);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn test_ordering_total() {
        let min_val = RowKeySQL::new(i64::MIN);
        let max_val = RowKeySQL::new(i64::MAX);
        assert!(min_val < max_val);
        assert!(max_val > min_val);
    }

    #[test]
    fn test_clone() {
        let a = RowKeySQL::new(99);
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.get_long(), b.get_long());
    }

    #[test]
    fn test_copy_semantics() {
        let a = RowKeySQL::new(100);
        let b = a;
        assert_eq!(a, b);
    }
}
