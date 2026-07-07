use std::collections::HashSet;
use std::fmt;

/// Organises long values into sets of values with overlapping bits.
///
/// For example, given values `1`, `2`, `3`, `8`, `12`:
/// - `1`, `2`, and `3` all use the `1`- or `2`-bit and therefore belong to the same group.
/// - `8` and `12` share the `8`-bit and form a separate group.
///
/// A `BitGroup` is seeded with a single value; additional values are incorporated by
/// calling [`merge`](BitGroup::merge) with another group whose [`mask`](BitGroup::get_mask)
/// overlaps with this one.
pub struct BitGroup {
    values: HashSet<i64>,
    mask: i64,
}

impl BitGroup {
    /// Creates a new `BitGroup` seeded with `value`.
    ///
    /// The initial mask equals `value` itself.
    pub(crate) fn new(value: i64) -> Self {
        let mut values = HashSet::new();
        values.insert(value);
        Self { values, mask: value }
    }

    /// Returns `true` if this group shares at least one bit with `other`.
    pub fn intersects(&self, other: &BitGroup) -> bool {
        (self.mask & other.mask) != 0
    }

    /// Merges `other` into this group.
    ///
    /// All values from `other` are added to this group and the masks are OR-ed together.
    pub fn merge(&mut self, other: &BitGroup) {
        self.values.extend(other.values.iter().copied());
        self.mask |= other.mask;
    }

    /// Returns the mask representing all bits used by the values in this group.
    pub fn get_mask(&self) -> i64 {
        self.mask
    }

    /// Returns the set of values that make up this group.
    pub fn get_values(&self) -> &HashSet<i64> {
        &self.values
    }
}

impl fmt::Display for BitGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitGroup - Mask: {:x} values: ", self.mask as u64)?;
        for value in &self.values {
            write!(f, "{},", value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_seeds_value_and_mask() {
        let g = BitGroup::new(3);
        assert_eq!(g.get_mask(), 3);
        assert!(g.get_values().contains(&3));
        assert_eq!(g.get_values().len(), 1);
    }

    #[test]
    fn intersects_overlapping_bits() {
        let a = BitGroup::new(0b0110);
        let b = BitGroup::new(0b0011);
        assert!(a.intersects(&b));
    }

    #[test]
    fn intersects_disjoint_bits() {
        let a = BitGroup::new(0b0100);
        let b = BitGroup::new(0b0011);
        assert!(!a.intersects(&b));
    }

    #[test]
    fn merge_combines_values_and_masks() {
        let mut a = BitGroup::new(1);
        let b = BitGroup::new(2);
        a.merge(&b);
        assert_eq!(a.get_mask(), 3);
        assert!(a.get_values().contains(&1));
        assert!(a.get_values().contains(&2));
        assert_eq!(a.get_values().len(), 2);
    }

    #[test]
    fn merge_deduplicates_values() {
        let mut a = BitGroup::new(1);
        let b = BitGroup::new(1);
        a.merge(&b);
        assert_eq!(a.get_values().len(), 1);
        assert_eq!(a.get_mask(), 1);
    }

    #[test]
    fn merge_example_from_docs() {
        // values 1, 2, 3: 1|2 == 3, so after merging groups for 1, 2, 3 the mask is 3
        let mut g = BitGroup::new(1);
        g.merge(&BitGroup::new(2));
        g.merge(&BitGroup::new(3));
        assert_eq!(g.get_mask(), 3);
        assert_eq!(g.get_values().len(), 3);
    }

    #[test]
    fn display_contains_mask_hex_and_values() {
        let g = BitGroup::new(255);
        let s = format!("{}", g);
        assert!(s.contains("ff"));
        assert!(s.contains("255"));
    }

    #[test]
    fn display_mask_treated_as_unsigned() {
        // i64::MIN has the high bit set; as u64 it is 8000000000000000
        let g = BitGroup::new(i64::MIN);
        let s = format!("{}", g);
        assert!(s.contains("8000000000000000"));
    }

    #[test]
    fn get_mask_reflects_merged_masks() {
        let mut a = BitGroup::new(8);
        a.merge(&BitGroup::new(12));
        // 8 | 12 == 12
        assert_eq!(a.get_mask(), 12);
    }

    #[test]
    fn intersects_self() {
        let g = BitGroup::new(7);
        assert!(g.intersects(&g));
    }

    #[test]
    fn zero_value_does_not_intersect_anything() {
        let z = BitGroup::new(0);
        let a = BitGroup::new(0xFF);
        assert!(!z.intersects(&a));
        assert!(!a.intersects(&z));
    }
}
