use std::cmp::Ordering;

/// Encodes the main hash value for an n-gram and the number of instructions hashed.
///
/// Mirrors Ghidra's `Hash`.
#[derive(Debug, Clone, Copy, Eq)]
pub struct Hash {
    /// Actual hash value.
    pub value: i32,
    /// Number of instructions involved in the hash.
    pub size: i32,
}

impl Hash {
    /// Initial accumulator value for the primary CRC hash function.
    pub const SEED: i32 = 22222;
    /// Initial accumulator value for the alternate hash function. Must differ from [`SEED`](Self::SEED).
    pub const ALTERNATE_SEED: i32 = 11111;

    pub fn new(value: i32, size: i32) -> Self {
        Self { value, size }
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.size == other.size
    }
}

// Java's hashCode() returns only `value`, producing the same collision profile.
impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Orders by `value` first, then by `size`, matching Java's `compareTo`.
impl Ord for Hash {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value).then(self.size.cmp(&other.size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_requires_both_fields() {
        let a = Hash::new(1, 2);
        let b = Hash::new(1, 2);
        let c = Hash::new(1, 3);
        let d = Hash::new(2, 2);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn ordering_by_value_first() {
        let lo = Hash::new(1, 99);
        let hi = Hash::new(2, 1);
        assert!(lo < hi);
    }

    #[test]
    fn ordering_by_size_when_value_equal() {
        let a = Hash::new(5, 1);
        let b = Hash::new(5, 2);
        assert!(a < b);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn seeds_have_correct_values() {
        assert_eq!(Hash::SEED, 22222);
        assert_eq!(Hash::ALTERNATE_SEED, 11111);
        assert_ne!(Hash::SEED, Hash::ALTERNATE_SEED);
    }

    #[test]
    fn hash_uses_only_value_field() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as _, Hasher};

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        // Same value, different size — hash must be equal (same as Java's hashCode)
        Hash::new(42, 1).hash(&mut h1);
        Hash::new(42, 99).hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}
