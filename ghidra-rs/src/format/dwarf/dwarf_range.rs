use std::cmp::Ordering;
use std::fmt;

/// Holds the start (inclusive) and end (exclusive, 1 past the last included address)
/// addresses of a range.
///
/// DWARF ranges are slightly different than Ghidra `AddressRange`s because the end
/// address of a Ghidra `AddressRange` is inclusive, and the DWARF range is exclusive.
///
/// DWARF ranges can represent an empty range, Ghidra `AddressRange`s can not.
/// Ghidra `AddressRange`s can include the maximum 64bit address (0xffffffffffffffff), but
/// DWARF ranges can not include that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFRange {
    start: u64,
    end: u64,
}

impl DWARFRange {
    pub const EMPTY: DWARFRange = DWARFRange { start: 0, end: 0 };

    /// Constructs a new [`DWARFRange`] using start and end values.
    ///
    /// # Panics
    /// Panics if `end` (unsigned) is less than `start` (unsigned).
    pub fn new(start: u64, end: u64) -> Self {
        if end < start {
            panic!("Range max ({:x}) cannot be less than min ({:x}).", end, start);
        }
        Self { start, end }
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end
    }

    /// Returns starting address.
    pub fn from(&self) -> u64 {
        self.start
    }

    /// Returns ending address, exclusive.
    pub fn to(&self) -> u64 {
        self.end
    }
}

impl fmt::Display for DWARFRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:x},{:x})", self.start, self.end)
    }
}

impl PartialOrd for DWARFRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DWARFRange {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start).then_with(|| self.end.cmp(&other.end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_constant_is_empty() {
        assert!(DWARFRange::EMPTY.is_empty());
        assert_eq!(DWARFRange::EMPTY.from(), 0);
        assert_eq!(DWARFRange::EMPTY.to(), 0);
    }

    #[test]
    fn new_range_reports_bounds() {
        let range = DWARFRange::new(0x10, 0x20);
        assert_eq!(range.from(), 0x10);
        assert_eq!(range.to(), 0x20);
        assert!(!range.is_empty());
    }

    #[test]
    fn zero_length_range_is_empty() {
        let range = DWARFRange::new(0x10, 0x10);
        assert!(range.is_empty());
    }

    #[test]
    #[should_panic]
    fn new_panics_when_end_before_start() {
        DWARFRange::new(0x20, 0x10);
    }

    #[test]
    fn contains_checks_half_open_interval() {
        let range = DWARFRange::new(0x10, 0x20);
        assert!(!range.contains(0x0f));
        assert!(range.contains(0x10));
        assert!(range.contains(0x1f));
        assert!(!range.contains(0x20));
    }

    #[test]
    fn contains_is_always_false_for_empty_range() {
        let range = DWARFRange::new(0x10, 0x10);
        assert!(!range.contains(0x10));
    }

    #[test]
    fn display_formats_as_half_open_hex_interval() {
        assert_eq!(DWARFRange::new(0x10, 0x20).to_string(), "[10,20)");
        assert_eq!(DWARFRange::EMPTY.to_string(), "[0,0)");
    }

    #[test]
    fn ordering_compares_start_then_end() {
        let a = DWARFRange::new(0x10, 0x20);
        let b = DWARFRange::new(0x10, 0x30);
        let c = DWARFRange::new(0x20, 0x20);
        assert!(a < b);
        assert!(b < c);
        assert_eq!(a.cmp(&a), Ordering::Equal);
    }

    #[test]
    fn ordering_treats_values_as_unsigned() {
        let low = DWARFRange::new(0x10, 0x20);
        let high = DWARFRange::new(u64::MAX - 1, u64::MAX);
        assert!(low < high);
    }
}
