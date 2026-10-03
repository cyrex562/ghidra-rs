//! Port of `ghidra.util.state.SequenceRange`.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::program::model::pcode::SequenceNumber;

/// A range between two [`SequenceNumber`]s. Port of `ghidra.util.state.SequenceRange`.
#[derive(Debug, Clone)]
pub struct SequenceRange {
    start: SequenceNumber,
    end: SequenceNumber,
}

impl SequenceRange {
    /// Port of `SequenceRange(SequenceNumber, SequenceNumber)`.
    pub fn new(start: SequenceNumber, end: SequenceNumber) -> Self {
        SequenceRange { start, end }
    }

    /// Port of `SequenceRange.getStart()`.
    pub fn get_start(&self) -> &SequenceNumber {
        &self.start
    }

    /// Port of `SequenceRange.getEnd()`.
    pub fn get_end(&self) -> &SequenceNumber {
        &self.end
    }

    /// Port of `SequenceRange.contains(SequenceNumber)`. Reimplements the comparison manually
    /// (rather than delegating to `SequenceNumber`'s own `Ord`) to mirror the real Java method
    /// body exactly, which does the same: compares target addresses first, falling back to
    /// `getTime()` only on a tie.
    pub fn contains(&self, seq: &SequenceNumber) -> bool {
        let addr = seq.get_target();
        let index = seq.get_time();
        let start_addr = self.start.get_target();
        let start_index = self.start.get_time();
        let end_addr = self.end.get_target();
        let end_index = self.end.get_time();

        let mut c = addr.cmp(start_addr);
        if c == Ordering::Equal {
            c = index.cmp(&start_index);
        }
        if c == Ordering::Less {
            return false;
        }

        let mut c2 = addr.cmp(end_addr);
        if c2 == Ordering::Equal {
            c2 = index.cmp(&end_index);
        }
        c2 != Ordering::Greater
    }
}

impl PartialEq for SequenceRange {
    /// Port of `SequenceRange.equals(Object)`.
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start && self.end == other.end
    }
}

impl Eq for SequenceRange {}

impl Hash for SequenceRange {
    /// Port of `SequenceRange.hashCode()`. Real Java hashes only `start` (not `end`) -- a
    /// faithfully-preserved quirk: two ranges sharing a `start` but with different `end`s hash
    /// equal even though they are not `equals`. This is legal under the hashCode/equals contract
    /// (only *equal* objects must hash equal; unequal objects may coincidentally hash equal too),
    /// just an unusually weak hash. See `hash_ignores_end_quirk` below.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start.hash(state);
    }
}

impl fmt::Display for SequenceRange {
    /// Port of `SequenceRange.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::address::Address;
    use std::collections::hash_map::DefaultHasher;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    fn seq(offset: i64, time: i32) -> SequenceNumber {
        SequenceNumber::new(addr(offset), time)
    }

    #[test]
    fn get_start_and_end() {
        let range = SequenceRange::new(seq(0x100, 0), seq(0x200, 0));
        assert_eq!(range.get_start(), &seq(0x100, 0));
        assert_eq!(range.get_end(), &seq(0x200, 0));
    }

    #[test]
    fn equals_compares_start_and_end() {
        let a = SequenceRange::new(seq(0x100, 0), seq(0x200, 0));
        let b = SequenceRange::new(seq(0x100, 0), seq(0x200, 0));
        let c = SequenceRange::new(seq(0x100, 0), seq(0x300, 0));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Faithful reproduction of the real Java quirk: `hashCode()` only hashes `start`, so two
    /// ranges with the same start but different ends hash equal despite not being `equals`.
    #[test]
    fn hash_ignores_end_quirk() {
        let a = SequenceRange::new(seq(0x100, 0), seq(0x200, 0));
        let b = SequenceRange::new(seq(0x100, 0), seq(0x999, 0));
        assert_ne!(a, b, "different ends: must not be equal");

        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish(), "hashCode ignores `end`, per real Java");
    }

    #[test]
    fn to_string_matches_java_format() {
        let range = SequenceRange::new(seq(0x100, 1), seq(0x200, 2));
        assert_eq!(range.to_string(), format!("{}-{}", seq(0x100, 1), seq(0x200, 2)));
    }

    #[test]
    fn contains_within_range_same_address_different_time() {
        let range = SequenceRange::new(seq(0x100, 1), seq(0x100, 5));
        assert!(range.contains(&seq(0x100, 1)));
        assert!(range.contains(&seq(0x100, 3)));
        assert!(range.contains(&seq(0x100, 5)));
        assert!(!range.contains(&seq(0x100, 0)));
        assert!(!range.contains(&seq(0x100, 6)));
    }

    #[test]
    fn contains_across_addresses() {
        let range = SequenceRange::new(seq(0x100, 5), seq(0x200, 2));
        // Below the start address entirely.
        assert!(!range.contains(&seq(0x50, 100)));
        // Between the two addresses.
        assert!(range.contains(&seq(0x150, 0)));
        // At the start address but before the start time.
        assert!(!range.contains(&seq(0x100, 4)));
        // At the start address at/after the start time.
        assert!(range.contains(&seq(0x100, 5)));
        assert!(range.contains(&seq(0x100, 99)));
        // At the end address but after the end time.
        assert!(!range.contains(&seq(0x200, 3)));
        // At the end address at/before the end time.
        assert!(range.contains(&seq(0x200, 2)));
        assert!(range.contains(&seq(0x200, 0)));
        // Beyond the end address entirely.
        assert!(!range.contains(&seq(0x300, 0)));
    }

    #[test]
    fn contains_single_point_range() {
        let range = SequenceRange::new(seq(0x100, 5), seq(0x100, 5));
        assert!(range.contains(&seq(0x100, 5)));
        assert!(!range.contains(&seq(0x100, 4)));
        assert!(!range.contains(&seq(0x100, 6)));
    }
}
