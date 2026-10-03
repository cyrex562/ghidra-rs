//! Port of `ghidra.trace.util.OverlappingObjectIterator`.
//!
//! An iterator of overlapping objects returned from two given iterators.
//!
//! The given iterators, named left and right, must return objects each having a range
//! attribute. Each iterator must return objects having disjoint ranges, i.e., no two
//! objects from the *same* iterator may intersect. Each iterator must also return the
//! objects sorted by min address. This iterator will then discover every case where an
//! object from the left iterator overlaps an object from the right iterator, and return
//! a pair for each such instance, in order of min address.
//!
//! **Difference from the Java original:** to avoid heap allocation on every `next()`, the
//! Java class reuses the same mutable `Pair` instance across calls -- its Javadoc warns
//! this causes "heap pollution" if a caller holds a reference across two `next()` calls
//! without copying it, since the fields mutate out from under them. Rust's ownership
//! model has no equivalent hazard: [`Iterator::next`] always hands back an owned value,
//! so this port yields a fresh `(L, R)` tuple (`L`/`R: Clone`) on each call instead of
//! aliasing shared mutable state. The *value* sequence produced is identical to Java's;
//! only the aliasing quirk (and its associated foot-gun) is absent by construction.

use crate::generic::util::peekable_iterator::PeekableIterator;
use crate::program::model::address::Address;
use std::cmp::Ordering;

/// A means of obtaining the range attribute from each object.
///
/// Mirrors the Java nested interface `OverlappingObjectIterator.Ranger<T>`.
pub trait Ranger<T> {
    /// Returns the minimum address of the range attribute of `t`.
    fn get_min_address(&self, t: &T) -> Address;
    /// Returns the maximum address of the range attribute of `t`.
    fn get_max_address(&self, t: &T) -> Address;
}

/// A [`Ranger`] for [`AddressRange`](crate::program::model::address::range::AddressRange).
///
/// Mirrors `OverlappingObjectIterator.AddressRangeRanger`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AddressRangeRanger;

impl Ranger<crate::program::model::address::range::AddressRange> for AddressRangeRanger {
    fn get_min_address(&self, t: &crate::program::model::address::range::AddressRange) -> Address {
        t.min_address().clone()
    }

    fn get_max_address(&self, t: &crate::program::model::address::range::AddressRange) -> Address {
        t.max_address().clone()
    }
}

/// A [`Ranger`] for a `(TraceAddressSnapRange, V)` map entry, keyed on the range's X axis.
///
/// Mirrors `OverlappingObjectIterator.SnapRangeKeyRanger`, which implements
/// `Ranger<Entry<TraceAddressSnapRange, ?>>`. The Rust port represents a map entry as a
/// `(K, V)` tuple (the convention already used elsewhere in this crate, e.g.
/// `ValueSortedMapEntryList<K, V>: LesserList<(K, V)>`), and is generic over the value
/// type `V` the way the Java wildcard `?` is.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SnapRangeKeyRanger;

impl<K, V> Ranger<(K, V)> for SnapRangeKeyRanger
where
    K: crate::trace::model::trace_address_snap_range::TraceAddressSnapRange,
{
    fn get_min_address(&self, t: &(K, V)) -> Address {
        t.0.get_x1()
    }

    fn get_max_address(&self, t: &(K, V)) -> Address {
        t.0.get_x2()
    }
}

/// A [`Ranger`] for `Arc<dyn CodeUnit>`.
///
/// Mirrors `OverlappingObjectIterator.CodeUnitRanger`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CodeUnitRanger;

impl Ranger<std::sync::Arc<dyn crate::program::model::listing::code_unit::CodeUnit>>
    for CodeUnitRanger
{
    fn get_min_address(
        &self,
        t: &std::sync::Arc<dyn crate::program::model::listing::code_unit::CodeUnit>,
    ) -> Address {
        t.get_min_address()
    }

    fn get_max_address(
        &self,
        t: &std::sync::Arc<dyn crate::program::model::listing::code_unit::CodeUnit>,
    ) -> Address {
        t.get_max_address()
    }
}

/// The `ADDRESS_RANGE` static ranger constant from the Java class.
pub const ADDRESS_RANGE: AddressRangeRanger = AddressRangeRanger;
/// The `SNAP_RANGE_KEY` static ranger constant from the Java class.
pub const SNAP_RANGE_KEY: SnapRangeKeyRanger = SnapRangeKeyRanger;
/// The `CODE_UNIT` static ranger constant from the Java class.
pub const CODE_UNIT: CodeUnitRanger = CodeUnitRanger;

/// An iterator of overlapping objects returned from two given iterators.
///
/// See the module-level docs for the full contract. Port of
/// `ghidra.trace.util.OverlappingObjectIterator<L, R>`.
pub struct OverlappingObjectIterator<L, R, LI, RI, LR, RR>
where
    LI: Iterator<Item = L>,
    RI: Iterator<Item = R>,
    LR: Ranger<L>,
    RR: Ranger<R>,
{
    left: LI,
    left_ranger: LR,
    right: RI,
    right_ranger: RR,

    next_l: Option<L>,
    next_r: Option<R>,

    /// Cache of the last `seek_next()` result, so repeated `peek()` calls (or a `peek()`
    /// followed by `next()`) don't repeat the search. Mirrors `AbstractPeekableIterator`'s
    /// `next`/`soughtNext` fields.
    cached: Option<(L, R)>,
    sought_next: bool,
}

impl<L, R, LI, RI, LR, RR> OverlappingObjectIterator<L, R, LI, RI, LR, RR>
where
    L: Clone,
    R: Clone,
    LI: Iterator<Item = L>,
    RI: Iterator<Item = R>,
    LR: Ranger<L>,
    RR: Ranger<R>,
{
    /// Creates a new overlapping-object iterator over the given left/right iterators and
    /// their rangers.
    pub fn new(left: LI, left_ranger: LR, right: RI, right_ranger: RR) -> Self {
        Self {
            left,
            left_ranger,
            right,
            right_ranger,
            next_l: None,
            next_r: None,
            cached: None,
            sought_next: false,
        }
    }

    fn check_seek_next(&mut self) {
        if !self.sought_next {
            self.sought_next = true;
            self.cached = self.seek_next();
        }
    }

    /// Port of `OverlappingObjectIterator.seekNext()`.
    fn seek_next(&mut self) -> Option<(L, R)> {
        if let Some(nl) = self.next_l.as_ref() {
            debug_assert!(self.next_r.is_some());
            let nr = self.next_r.as_ref().unwrap();
            let cmp = self
                .left_ranger
                .get_max_address(nl)
                .cmp(&self.right_ranger.get_max_address(nr));
            if cmp != Ordering::Greater {
                self.next_l = None; // Cause left to advance
            }
            if cmp != Ordering::Less {
                // Yes, both should advance if maxes are equal
                self.next_r = None; // Cause right to advance
            }
        } else {
            debug_assert!(self.next_r.is_none());
        }

        if self.next_l.is_none() {
            match self.left.next() {
                Some(v) => self.next_l = Some(v),
                None => return None,
            }
        }
        if self.next_r.is_none() {
            match self.right.next() {
                Some(v) => self.next_r = Some(v),
                None => return None,
            }
        }

        loop {
            let nl = self.next_l.as_ref().unwrap();
            let nr = self.next_r.as_ref().unwrap();

            if self.left_ranger.get_max_address(nl) < self.right_ranger.get_min_address(nr) {
                match self.left.next() {
                    Some(v) => {
                        self.next_l = Some(v);
                        continue;
                    }
                    None => {
                        self.next_l = None;
                        return None;
                    }
                }
            }
            if self.right_ranger.get_max_address(nr) < self.left_ranger.get_min_address(nl) {
                match self.right.next() {
                    Some(v) => {
                        self.next_r = Some(v);
                        continue;
                    }
                    None => {
                        self.next_r = None;
                        return None;
                    }
                }
            }
            // Left and right overlap!
            return Some((nl.clone(), nr.clone()));
        }
    }
}

impl<L, R, LI, RI, LR, RR> Iterator for OverlappingObjectIterator<L, R, LI, RI, LR, RR>
where
    L: Clone,
    R: Clone,
    LI: Iterator<Item = L>,
    RI: Iterator<Item = R>,
    LR: Ranger<L>,
    RR: Ranger<R>,
{
    type Item = (L, R);

    fn next(&mut self) -> Option<Self::Item> {
        self.check_seek_next();
        self.sought_next = false;
        self.cached.take()
    }
}

impl<L, R, LI, RI, LR, RR> PeekableIterator for OverlappingObjectIterator<L, R, LI, RI, LR, RR>
where
    L: Clone,
    R: Clone,
    LI: Iterator<Item = L>,
    RI: Iterator<Item = R>,
    LR: Ranger<L>,
    RR: Ranger<R>,
{
    fn peek(&mut self) -> Option<&Self::Item> {
        self.check_seek_next();
        self.cached.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn create_test_address_space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn rng(space: &Arc<AddressSpace>, min: i64, max: i64) -> AddressRange {
        AddressRange::new(addr(space, min), addr(space, max))
    }

    fn overlaps(
        a: Vec<AddressRange>,
        b: Vec<AddressRange>,
    ) -> Vec<(AddressRange, AddressRange)> {
        OverlappingObjectIterator::new(
            a.into_iter(),
            AddressRangeRanger,
            b.into_iter(),
            AddressRangeRanger,
        )
        .collect()
    }

    #[test]
    fn test_empty() {
        let space = create_test_address_space();
        assert_eq!(overlaps(vec![], vec![]), vec![]);
        assert_eq!(overlaps(vec![], vec![rng(&space, 0x1000, 0x1fff)]), vec![]);
        assert_eq!(overlaps(vec![rng(&space, 0x1000, 0x1fff)], vec![]), vec![]);
    }

    #[test]
    fn test_disjoint() {
        let space = create_test_address_space();
        let a = vec![rng(&space, 0x1000, 0x1fff), rng(&space, 0x4000, 0x4fff)];
        let b = vec![rng(&space, 0x2000, 0x2fff), rng(&space, 0x6000, 0x6fff)];

        assert_eq!(overlaps(a.clone(), b.clone()), vec![]);
        assert_eq!(overlaps(b, a), vec![]);
    }

    #[test]
    fn test_ends_overlap() {
        let space = create_test_address_space();
        let a = vec![rng(&space, 0x1000, 0x2fff)];
        let b = vec![rng(&space, 0x2000, 0x3fff)];

        assert_eq!(
            overlaps(a.clone(), b.clone()),
            vec![(rng(&space, 0x1000, 0x2fff), rng(&space, 0x2000, 0x3fff))]
        );
        assert_eq!(
            overlaps(b, a),
            vec![(rng(&space, 0x2000, 0x3fff), rng(&space, 0x1000, 0x2fff))]
        );
    }

    #[test]
    fn test_one_enclosed() {
        let space = create_test_address_space();
        let a = vec![rng(&space, 0x1000, 0x3fff)];
        let b = vec![rng(&space, 0x2000, 0x2fff)];

        assert_eq!(
            overlaps(a.clone(), b.clone()),
            vec![(rng(&space, 0x1000, 0x3fff), rng(&space, 0x2000, 0x2fff))]
        );
        assert_eq!(
            overlaps(b, a),
            vec![(rng(&space, 0x2000, 0x2fff), rng(&space, 0x1000, 0x3fff))]
        );
    }

    #[test]
    fn test_same() {
        let space = create_test_address_space();
        let a = vec![rng(&space, 0x1000, 0x1fff)];
        let b = vec![rng(&space, 0x1000, 0x1fff)];

        assert_eq!(
            overlaps(a, b),
            vec![(rng(&space, 0x1000, 0x1fff), rng(&space, 0x1000, 0x1fff))]
        );
    }

    #[test]
    fn test_staggered() {
        let space = create_test_address_space();
        let a = vec![rng(&space, 0x1000, 0x3fff), rng(&space, 0x5000, 0x7fff)];
        let b = vec![rng(&space, 0x3000, 0x5fff), rng(&space, 0x7000, 0x9fff)];

        assert_eq!(
            overlaps(a.clone(), b.clone()),
            vec![
                (rng(&space, 0x1000, 0x3fff), rng(&space, 0x3000, 0x5fff)),
                (rng(&space, 0x5000, 0x7fff), rng(&space, 0x3000, 0x5fff)),
                (rng(&space, 0x5000, 0x7fff), rng(&space, 0x7000, 0x9fff)),
            ]
        );
        assert_eq!(
            overlaps(b, a),
            vec![
                (rng(&space, 0x3000, 0x5fff), rng(&space, 0x1000, 0x3fff)),
                (rng(&space, 0x3000, 0x5fff), rng(&space, 0x5000, 0x7fff)),
                (rng(&space, 0x7000, 0x9fff), rng(&space, 0x5000, 0x7fff)),
            ]
        );
    }

    #[test]
    fn test_two_enclosed() {
        let space = create_test_address_space();
        let a = vec![rng(&space, 0x1000, 0x5fff)];
        let b = vec![rng(&space, 0x2000, 0x2fff), rng(&space, 0x4000, 0x4fff)];

        assert_eq!(
            overlaps(a.clone(), b.clone()),
            vec![
                (rng(&space, 0x1000, 0x5fff), rng(&space, 0x2000, 0x2fff)),
                (rng(&space, 0x1000, 0x5fff), rng(&space, 0x4000, 0x4fff)),
            ]
        );
        assert_eq!(
            overlaps(b, a),
            vec![
                (rng(&space, 0x2000, 0x2fff), rng(&space, 0x1000, 0x5fff)),
                (rng(&space, 0x4000, 0x4fff), rng(&space, 0x1000, 0x5fff)),
            ]
        );
    }

    /// Verifies the PeekableIterator surface (peek() does not advance; repeated peek()
    /// returns the same pair) works on top of OverlappingObjectIterator, matching the
    /// `PeekableIterator` contract the Java class inherits via `AbstractPeekableIterator`.
    #[test]
    fn test_peek_does_not_advance() {
        let space = create_test_address_space();
        let a = vec![rng(&space, 0x1000, 0x2fff)];
        let b = vec![rng(&space, 0x2000, 0x3fff)];
        let mut it = OverlappingObjectIterator::new(
            a.into_iter(),
            AddressRangeRanger,
            b.into_iter(),
            AddressRangeRanger,
        );

        let expected = (rng(&space, 0x1000, 0x2fff), rng(&space, 0x2000, 0x3fff));
        assert_eq!(it.peek(), Some(&expected));
        assert_eq!(it.peek(), Some(&expected));
        assert_eq!(it.next(), Some(expected));
        assert_eq!(it.peek(), None);
        assert_eq!(it.next(), None);
    }
}
