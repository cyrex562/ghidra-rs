use std::fmt;
use std::hash::{Hash, Hasher};

use crate::program::model::address::Address;

/// Represents a match of a pattern at a given address in program memory.
///
/// # Type Parameters
/// - `T`: The specific implementation of the byte pattern that produced this match.
#[derive(Debug, Clone)]
pub struct AddressMatch<T> {
    pattern: T,
    start: u64,
    length: usize,
    address: Address,
}

impl<T> AddressMatch<T> {
    /// Constructs an `AddressMatch` of a byte pattern that matched at a position in the
    /// program.
    ///
    /// - `pattern`: the byte pattern that matched.
    /// - `start`: the offset in the buffer where the match begins.
    /// - `length`: the length in bytes of the matching sequence.
    /// - `address`: the address in the program where the match occurred.
    pub fn new(pattern: T, start: u64, length: usize, address: Address) -> Self {
        Self {
            pattern,
            start,
            length,
            address,
        }
    }

    /// Returns the length in bytes of the matched pattern.
    pub fn get_length(&self) -> usize {
        self.length
    }

    /// Returns the offset of the match in the buffer.
    pub fn get_start(&self) -> u64 {
        self.start
    }

    /// Returns the pattern that was matched.
    pub fn get_pattern(&self) -> &T {
        &self.pattern
    }

    /// Returns the address where this match occurred.
    pub fn get_address(&self) -> &Address {
        &self.address
    }
}

impl<T: fmt::Display> fmt::Display for AddressMatch<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {}", self.pattern, self.address)
    }
}

impl<T: PartialEq> PartialEq for AddressMatch<T> {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
            && self.start == other.start
            && self.length == other.length
            && self.address == other.address
    }
}

impl<T: Eq> Eq for AddressMatch<T> {}

impl<T: Hash> Hash for AddressMatch<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
        self.start.hash(state);
        self.length.hash(state);
        self.address.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::AddressMatch;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::Arc;

    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut h = DefaultHasher::new();
        val.hash(&mut h);
        h.finish()
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn getters_return_correct_fields() {
        let addr = test_address(0x1000);
        let m = AddressMatch::new("pat", 42u64, 3usize, addr.clone());
        assert_eq!(m.get_pattern(), &"pat");
        assert_eq!(m.get_start(), 42);
        assert_eq!(m.get_length(), 3);
        assert_eq!(m.get_address(), &addr);
    }

    #[test]
    fn display_formats_pattern_and_address() {
        let addr = test_address(0x2000);
        let m = AddressMatch::new("hello", 100u64, 5usize, addr.clone());
        let display_str = m.to_string();
        assert!(display_str.contains("hello"));
        assert!(display_str.contains("@"));
    }

    #[test]
    fn equal_matches_are_equal() {
        let addr = test_address(0x3000);
        let a = AddressMatch::new(0xDEADu32, 0u64, 2usize, addr.clone());
        let b = AddressMatch::new(0xDEADu32, 0u64, 2usize, addr.clone());
        assert_eq!(a, b);
    }

    #[test]
    fn different_pattern_not_equal() {
        let addr = test_address(0x4000);
        let a = AddressMatch::new(0x01u32, 0u64, 1usize, addr.clone());
        let b = AddressMatch::new(0x02u32, 0u64, 1usize, addr.clone());
        assert_ne!(a, b);
    }

    #[test]
    fn different_start_not_equal() {
        let addr = test_address(0x5000);
        let a = AddressMatch::new(0x01u32, 0u64, 1usize, addr.clone());
        let b = AddressMatch::new(0x01u32, 1u64, 1usize, addr.clone());
        assert_ne!(a, b);
    }

    #[test]
    fn different_length_not_equal() {
        let addr = test_address(0x6000);
        let a = AddressMatch::new(0x01u32, 0u64, 1usize, addr.clone());
        let b = AddressMatch::new(0x01u32, 0u64, 2usize, addr.clone());
        assert_ne!(a, b);
    }

    #[test]
    fn different_address_not_equal() {
        let addr1 = test_address(0x7000);
        let addr2 = test_address(0x7001);
        let a = AddressMatch::new(0x01u32, 0u64, 1usize, addr1);
        let b = AddressMatch::new(0x01u32, 0u64, 1usize, addr2);
        assert_ne!(a, b);
    }

    #[test]
    fn equal_matches_have_equal_hashes() {
        let addr = test_address(0x8000);
        let a = AddressMatch::new(0xABu32, 7u64, 4usize, addr.clone());
        let b = AddressMatch::new(0xABu32, 7u64, 4usize, addr.clone());
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn zero_length_match_is_valid() {
        let addr = test_address(0x9000);
        let m = AddressMatch::new("x", 0u64, 0usize, addr);
        assert_eq!(m.get_length(), 0);
        assert_eq!(m.get_start(), 0);
    }

    #[test]
    fn large_start_offset_preserved() {
        let addr = test_address(0xA000);
        let start = u64::MAX;
        let m = AddressMatch::new(1u8, start, 1usize, addr);
        assert_eq!(m.get_start(), u64::MAX);
    }
}
