//! Port of `ghidra.app.util.bin.format.dwarf.DWARFLocation`.

use crate::format::dwarf::dwarf_range::DWARFRange;
use crate::program::model::pcode::Varnode;

/// Represents the location of an item that is only valid for a certain range of program-counter
/// locations.
///
/// An instance that does not have a [`DWARFRange`] is considered valid for any pc.
///
/// # Differences from Java
///
/// Java's `DWARFLocation` does not override `equals`/`hashCode`, so two instances with identical
/// fields are unequal under Java's default (reference) equality. This port derives `PartialEq`/
/// `Eq` by value instead -- the same simplification this crate already uses for other plain data
/// classes ported without their own `equals` (e.g. [`DWARFRange`]) -- since nothing in this crate
/// relies on `DWARFLocation` reference identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFLocation {
    /// `None` mirrors a `null` `addressRange`, which Java treats as "valid for any pc"
    /// (`isWildcard()`).
    address_range: Option<DWARFRange>,
    expr: Vec<u8>,
    resolved_value: Option<Varnode>,
}

impl DWARFLocation {
    /// Create a Location given an address range and location expression.
    ///
    /// Port of `DWARFLocation(long start, long end, byte[] expr)`.
    pub fn from_bounds(start: u64, end: u64, expr: Vec<u8>) -> Self {
        Self::new(DWARFRange::new(start, end), expr)
    }

    /// Port of `DWARFLocation(DWARFRange addressRange, byte[] expr)`.
    pub fn new(address_range: DWARFRange, expr: Vec<u8>) -> Self {
        DWARFLocation { address_range: Some(address_range), expr, resolved_value: None }
    }

    /// Rust-only convenience matching the effect of Java's `new DWARFLocation(null, expr)`: a
    /// wildcard location, valid for any pc. Java has no dedicated constructor for this case
    /// (callers pass a literal `null`), but Rust has no `null` to pass through the two-argument
    /// constructor, so this crate exposes it directly.
    pub fn wildcard(expr: Vec<u8>) -> Self {
        DWARFLocation { address_range: None, expr, resolved_value: None }
    }

    /// Port of `DWARFLocation.getRange()`.
    pub fn get_range(&self) -> Option<DWARFRange> {
        self.address_range
    }

    /// Port of `DWARFLocation.getExpr()`.
    pub fn get_expr(&self) -> &[u8] {
        &self.expr
    }

    /// Port of `DWARFLocation.isWildcard()`.
    pub fn is_wildcard(&self) -> bool {
        self.address_range.is_none()
    }

    /// Port of `DWARFLocation.getOffset(long)`.
    ///
    /// # Differences from Java
    ///
    /// Faithfully reproduces Java's `addressRange.getFrom() - pc` -- the *range start* minus
    /// `pc`, not the more intuitive `pc - start` ("how far into the range is `pc`"). For a `pc`
    /// that falls inside the range (the only case callers use this for), the range start is
    /// less than or equal to `pc`, so this value is `<= 0`; see
    /// [`get_offset_is_range_start_minus_pc_not_pc_minus_start`] for a test pinning that
    /// direction. Returns `0` for a wildcard location, matching Java's `addressRange != null ? ...
    /// : 0`.
    pub fn get_offset(&self, pc: u64) -> i64 {
        match self.address_range {
            Some(range) => (range.from() as i64).wrapping_sub(pc as i64),
            None => 0,
        }
    }

    /// Port of `DWARFLocation.contains(long)`.
    pub fn contains(&self, addr: u64) -> bool {
        self.is_wildcard() || self.address_range.unwrap().contains(addr)
    }

    /// Port of `DWARFLocation.getResolvedValue()`.
    pub fn get_resolved_value(&self) -> Option<&Varnode> {
        self.resolved_value.as_ref()
    }

    /// Port of `DWARFLocation.setResolvedValue(Varnode)`.
    ///
    /// Takes `Option<Varnode>` rather than a bare `Varnode` since Java's setter accepts `null` to
    /// clear the cached value.
    pub fn set_resolved_value(&mut self, resolved_value: Option<Varnode>) {
        self.resolved_value = resolved_value;
    }
}

impl std::fmt::Display for DWARFLocation {
    /// Port of `DWARFLocation.toString()`: `"DWARFLocation: range: %s, expr: %s".formatted(...)`.
    ///
    /// Java's `%s` on a `null` `addressRange` prints the literal string `"null"`; `Arrays
    /// .toString(byte[])` prints comma-separated decimal bytes in brackets, which matches Rust's
    /// `{:?}` on `Vec<u8>`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let range_str =
            self.address_range.map(|r| r.to_string()).unwrap_or_else(|| "null".to_string());
        write!(f, "DWARFLocation: range: {}, expr: {:?}", range_str, self.expr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bounds_constructs_range() {
        let loc = DWARFLocation::from_bounds(0x10, 0x20, vec![1, 2]);
        assert!(!loc.is_wildcard());
        assert_eq!(loc.get_range(), Some(DWARFRange::new(0x10, 0x20)));
        assert_eq!(loc.get_expr(), &[1, 2]);
    }

    #[test]
    fn new_constructs_from_range() {
        let range = DWARFRange::new(0x100, 0x200);
        let loc = DWARFLocation::new(range, vec![0xff]);
        assert_eq!(loc.get_range(), Some(range));
        assert_eq!(loc.get_expr(), &[0xff]);
    }

    #[test]
    fn wildcard_has_no_range() {
        let loc = DWARFLocation::wildcard(vec![0x03]);
        assert!(loc.is_wildcard());
        assert_eq!(loc.get_range(), None);
    }

    #[test]
    fn contains_checks_range_for_non_wildcard() {
        let loc = DWARFLocation::from_bounds(0x10, 0x20, vec![]);
        assert!(!loc.contains(0x0f));
        assert!(loc.contains(0x10));
        assert!(loc.contains(0x1f));
        assert!(!loc.contains(0x20));
    }

    #[test]
    fn contains_is_always_true_for_wildcard() {
        let loc = DWARFLocation::wildcard(vec![]);
        assert!(loc.contains(0));
        assert!(loc.contains(u64::MAX));
    }

    /// Java: `getOffset` returns `addressRange.getFrom() - pc`, i.e. range-start minus pc, not
    /// pc minus range-start. For a `pc` inside `[0x10, 0x20)`, that makes the offset zero or
    /// negative (`0x10 - 0x15 == -5`), which reads backwards from what "offset into the range"
    /// would suggest. This pins that exact (quirky) direction so a future "fix" doesn't silently
    /// flip it.
    #[test]
    fn get_offset_is_range_start_minus_pc_not_pc_minus_start() {
        let loc = DWARFLocation::from_bounds(0x10, 0x20, vec![]);
        assert_eq!(loc.get_offset(0x15), -5);
        assert_eq!(loc.get_offset(0x10), 0);
        // pc before the range: still start - pc, now positive.
        assert_eq!(loc.get_offset(0x05), 0x0b);
    }

    #[test]
    fn get_offset_is_zero_for_wildcard() {
        let loc = DWARFLocation::wildcard(vec![]);
        assert_eq!(loc.get_offset(0x1234), 0);
    }

    #[test]
    fn resolved_value_defaults_to_none() {
        let loc = DWARFLocation::wildcard(vec![]);
        assert_eq!(loc.get_resolved_value(), None);
    }

    #[test]
    fn resolved_value_round_trips() {
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

        let mut loc = DWARFLocation::wildcard(vec![]);
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x42);
        let vn = Varnode::new(addr, 4);
        loc.set_resolved_value(Some(vn.clone()));
        assert_eq!(loc.get_resolved_value(), Some(&vn));

        loc.set_resolved_value(None);
        assert_eq!(loc.get_resolved_value(), None);
    }

    #[test]
    fn display_matches_java_format_for_ranged_location() {
        let loc = DWARFLocation::from_bounds(0x10, 0x20, vec![1]);
        assert_eq!(loc.to_string(), "DWARFLocation: range: [10,20), expr: [1]");
    }

    #[test]
    fn display_matches_java_format_for_wildcard() {
        let loc = DWARFLocation::wildcard(vec![]);
        assert_eq!(loc.to_string(), "DWARFLocation: range: null, expr: []");
    }
}
