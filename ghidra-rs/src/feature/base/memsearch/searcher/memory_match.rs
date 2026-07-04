use std::cmp::Ordering;
use std::fmt;

use crate::program::model::address::Address;

/// A class that represents a memory search hit at an address. Matches can also be updated with
/// new byte values (from a scan or refresh action). The original bytes that matched the original
/// search are maintained in addition to the "refreshed" bytes.
///
/// # Type Parameters
/// - `T`: The client object type that identifies the matching pattern
#[derive(Clone, Debug)]
pub struct MemoryMatch<T> {
    address: Address,
    bytes: Vec<u8>,
    previous_bytes: Vec<u8>,
    pattern: Option<T>,
}

impl<T> MemoryMatch<T> {
    /// Creates a new `MemoryMatch` with the given address, matched bytes, and pattern.
    ///
    /// # Panics
    /// Panics if `bytes` is empty.
    pub fn new(address: Address, bytes: Vec<u8>, pattern: T) -> Self {
        if bytes.is_empty() {
            panic!("Must provide at least 1 byte");
        }
        Self {
            address,
            previous_bytes: bytes.clone(),
            bytes,
            pattern: Some(pattern),
        }
    }

    /// Creates a new `MemoryMatch` with only an address, no bytes or pattern.
    pub fn from_address(address: Address) -> Self {
        Self {
            address,
            bytes: Vec::new(),
            previous_bytes: Vec::new(),
            pattern: None,
        }
    }

    /// Updates the current bytes, retaining the prior bytes as the "previous" bytes.
    pub fn update_bytes(&mut self, new_bytes: Vec<u8>) {
        self.previous_bytes = std::mem::replace(&mut self.bytes, new_bytes);
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn length(&self) -> usize {
        self.bytes.len()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn previous_bytes(&self) -> &[u8] {
        &self.previous_bytes
    }

    pub fn pattern(&self) -> Option<&T> {
        self.pattern.as_ref()
    }

    /// Returns true if the current bytes differ from the previous bytes.
    pub fn is_changed(&self) -> bool {
        self.bytes != self.previous_bytes
    }
}

impl<T> fmt::Display for MemoryMatch<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl<T> PartialEq for MemoryMatch<T> {
    // Just compare addresses. The bytes are mutable and we want matches to be equal even
    // if the bytes are different.
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl<T> Eq for MemoryMatch<T> {}

impl<T> std::hash::Hash for MemoryMatch<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl<T> PartialOrd for MemoryMatch<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for MemoryMatch<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(Arc::new(space), offset)
    }

    #[test]
    #[should_panic(expected = "Must provide at least 1 byte")]
    fn new_panics_on_empty_bytes() {
        MemoryMatch::new(addr(0x100), Vec::new(), 42u32);
    }

    #[test]
    fn new_sets_bytes_and_pattern() {
        let m = MemoryMatch::new(addr(0x100), vec![1, 2, 3], 42u32);
        assert_eq!(m.bytes(), &[1, 2, 3]);
        assert_eq!(m.previous_bytes(), &[1, 2, 3]);
        assert_eq!(m.pattern(), Some(&42u32));
        assert_eq!(m.length(), 3);
        assert!(!m.is_changed());
    }

    #[test]
    fn from_address_has_no_pattern_or_bytes() {
        let m: MemoryMatch<u32> = MemoryMatch::from_address(addr(0x200));
        assert_eq!(m.pattern(), None);
        assert_eq!(m.bytes(), &[] as &[u8]);
        assert_eq!(m.length(), 0);
    }

    #[test]
    fn update_bytes_tracks_previous_and_changed_state() {
        let mut m = MemoryMatch::new(addr(0x100), vec![1, 2, 3], "pat");
        m.update_bytes(vec![9, 9, 9]);
        assert_eq!(m.bytes(), &[9, 9, 9]);
        assert_eq!(m.previous_bytes(), &[1, 2, 3]);
        assert!(m.is_changed());

        m.update_bytes(vec![9, 9, 9]);
        assert!(!m.is_changed());
    }

    #[test]
    fn equality_and_hash_only_consider_address() {
        let mut a = MemoryMatch::new(addr(0x100), vec![1], "x");
        let b = MemoryMatch::new(addr(0x100), vec![2], "y");
        assert_eq!(a, b);

        a.update_bytes(vec![0xFF]);
        assert_eq!(a, b, "changing bytes must not affect equality");

        let c = MemoryMatch::new(addr(0x200), vec![1], "x");
        assert_ne!(a, c);
    }

    #[test]
    fn ordering_follows_address() {
        let low = MemoryMatch::new(addr(0x100), vec![1], "x");
        let high = MemoryMatch::new(addr(0x200), vec![1], "x");
        assert!(low < high);
        assert_eq!(low.cmp(&low), Ordering::Equal);
    }

    #[test]
    fn display_shows_address() {
        let m = MemoryMatch::new(addr(0x100), vec![1], "x");
        assert_eq!(m.to_string(), addr(0x100).to_string());
    }
}
