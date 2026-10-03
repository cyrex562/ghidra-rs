//! Port of `ghidra.taint.model.TaintVec`.
//!
//! A mutable, but fixed-size, buffer of taint sets.
//!
//! This is the auxiliary type used by the Taint Analyzer's emulator.
//!
//! Regarding serialization, we do not serialize the vector for storage, but only for display. For
//! storage, we instead serialize and store each taint set on an address-by-address basis. Thus, we
//! do not (yet) have a `parse(String)` method.
//!
//! # Deviations from Java
//!
//! Java's `withOp(PcodeOp)` returns a new `TaintVec` that *aliases* the same backing `TaintSet[]`
//! array as the vector it was called on (the private constructor it delegates to just stores the
//! array reference it is given, rather than copying it) -- so mutating either vector's elements
//! afterward (via [`TaintVec::set`] and friends) is visible through the other one too. This crate
//! follows its established, crate-wide convention of representing a Java object's fields as
//! plain owned Rust values (here, `Vec<TaintSet>`) rather than modeling Java's general
//! object-reference-sharing semantics with something like `Rc<RefCell<_>>`, so
//! [`TaintVec::with_op`] instead returns an independent copy of the sets, tagged with the new op.
//! Nothing in this crate's ported call sites mutates a vector after tagging it this way, so this
//! is not expected to be observable.
use std::collections::HashSet;
use std::fmt;

use crate::program::model::pcode::PcodeOp;

use super::{TaintMark, TaintSet};

/// A mutable, but fixed-size, buffer of taint sets.
#[derive(Debug, Clone)]
pub struct TaintVec {
    sets: Vec<TaintSet>,
    /// The length of the vector. Java: `public final int length`.
    pub length: usize,
    originating_op: Option<PcodeOp>,
}

impl TaintVec {
    /// Create a vector of taint sets. Java: the varargs `of(PcodeOp op, TaintSet... taints)`.
    pub fn of(op: PcodeOp, taints: Vec<TaintSet>) -> TaintVec {
        TaintVec::from_sets(taints, Some(op))
    }

    /// Create a vector of empty taint sets. Java: `empties(int size)`.
    pub fn empties(size: usize) -> TaintVec {
        TaintVec::copies(TaintSet::default(), size)
    }

    /// Broadcast the given set into a new vector or the given length. Java: `copies(TaintSet
    /// taint, int size)`.
    pub fn copies(taint: TaintSet, size: usize) -> TaintVec {
        let mut vec = TaintVec::new(size);
        vec.set_copies(taint);
        vec
    }

    /// Create a taint vector representing a new tainted byte array, where each element is given a
    /// distinct name.
    ///
    /// For example, the parameters `("arr", 0, 4)` will produce the vector
    /// "`[arr_0][arr_1][arr_2][arr_3]`". Each element is a singleton set containing the mark for a
    /// byte in the tainted array.
    ///
    /// Java: `array(String name, long start, int size)`.
    pub fn array(name: &str, start: i64, size: usize) -> TaintVec {
        let mut vec = TaintVec::new(size);
        vec.set_array(name, start);
        vec
    }

    fn from_sets(sets: Vec<TaintSet>, op: Option<PcodeOp>) -> TaintVec {
        let length = sets.len();
        TaintVec { sets, length, originating_op: op }
    }

    /// Create a new uninitialized taint vector of the given length. Java: `TaintVec(int
    /// length)`.
    pub fn new(length: usize) -> TaintVec {
        TaintVec::from_sets(vec![TaintSet::default(); length], None)
    }

    /// Create a new uninitialized taint vector of the given length, with an originating op. Java:
    /// `TaintVec(int length, PcodeOp op)`.
    pub fn new_with_op(length: usize, op: PcodeOp) -> TaintVec {
        TaintVec::from_sets(vec![TaintSet::default(); length], Some(op))
    }

    /// Convert the vector to a string suitable for display in the UI. Java: `toDisplay()`.
    pub fn to_display(&self) -> String {
        self.sets.iter().map(|e| format!("[{}]", e)).collect::<Vec<_>>().join("")
    }

    /// Get the vector as a list. Java: `getSets()`.
    pub fn get_sets(&self) -> &[TaintSet] {
        &self.sets
    }

    /// Get an element from the vector. Java: `get(int i)`.
    pub fn get(&self, i: usize) -> &TaintSet {
        &self.sets[i]
    }

    /// Set an element in the vector. Java: `set(int i, TaintSet s)`.
    pub fn set(&mut self, i: usize, s: TaintSet) {
        self.sets[i] = s;
    }

    /// Set several elements in the vector.
    ///
    /// This is essentially just an array copy. The entire source `vec` is copied into this
    /// vector such that the first element of the source is placed at the start index of the
    /// destination.
    ///
    /// Java: `TaintVec set(int start, TaintVec vec)`.
    pub fn set_range(&mut self, start: usize, vec: &TaintVec) -> &mut Self {
        for i in 0..vec.length {
            self.sets[i + start] = vec.sets[i].clone();
        }
        self
    }

    /// Perform an operation on each same-indexed element from this and another vector, forming a
    /// third result vector.
    ///
    /// In essence, return a vector where `result[n] = this[n] op that[n]`. The two input vectors
    /// must match in length.
    ///
    /// # Panics
    /// Panics if the lengths of `self` and `that` differ, mirroring Java's
    /// `IllegalArgumentException`.
    fn zip(&self, that: &TaintVec, op: impl Fn(&TaintSet, &TaintSet) -> TaintSet) -> TaintVec {
        let length = self.sets.len();
        if length != that.sets.len() {
            panic!("TaintVecs must match in length");
        }
        let mut vec = TaintVec::new(length);
        for i in 0..length {
            vec.sets[i] = op(&self.sets[i], &that.sets[i]);
        }
        vec
    }

    /// Perform an operation on a given taint set and each element from this array, forming a
    /// result vector.
    ///
    /// In essence, return a vector where `result[n] = this[n] op set`.
    fn each(&self, set: &TaintSet, op: impl Fn(&TaintSet, &TaintSet) -> TaintSet) -> TaintVec {
        let length = self.sets.len();
        let mut vec = TaintVec::new(length);
        for i in 0..length {
            vec.sets[i] = op(&self.sets[i], set);
        }
        vec
    }

    /// Union each element with its corresponding element from another vector, forming a new
    /// result vector. Java: `zipUnion(TaintVec that)`.
    pub fn zip_union(&self, that: &TaintVec) -> TaintVec {
        self.zip(that, TaintSet::union)
    }

    /// Union each element with the given set, forming a new result vector. Java: `eachUnion(
    /// TaintSet set)`.
    pub fn each_union(&self, set: &TaintSet) -> TaintVec {
        self.each(set, TaintSet::union)
    }

    /// Reduce this vector to a single taint set by union. Java: `union()`.
    pub fn union(&self) -> TaintSet {
        let mut result: HashSet<TaintMark> = HashSet::new();
        for s in &self.sets {
            result.extend(s.marks().iter().cloned());
        }
        TaintSet::of(result)
    }

    /// Combine this and another taint vector to represent a tainted indirect read.
    ///
    /// Because all bytes of the address offset "affect" the value read, we first union all the
    /// taint sets of that offset. We then tag each mark in that union with "`indR`". Finally we
    /// union that result with each element of this vector (this vector representing the bytes
    /// read from memory).
    ///
    /// Java: `tagIndirectRead(TaintVec offset)`.
    pub fn tag_indirect_read(&self, offset: &TaintVec) -> TaintVec {
        let taint_offset = offset.union().tagged("indR");
        self.each_union(&taint_offset)
    }

    /// Combine this and another taint vector to represent a tainted indirect write.
    ///
    /// This works the same as [`TaintVec::tag_indirect_read`], except with the tag "`indW`" and
    /// it occurs before the actual write.
    ///
    /// Java: `tagIndirectWrite(TaintVec offset)`.
    pub fn tag_indirect_write(&self, offset: &TaintVec) -> TaintVec {
        let taint_offset = offset.union().tagged("indW");
        self.each_union(&taint_offset)
    }

    /// Broadcast the given set over this vector, modifying it in place. Java: `TaintVec
    /// setCopies(TaintSet taint)`.
    pub fn set_copies(&mut self, taint: TaintSet) -> &mut Self {
        for i in 0..self.length {
            self.sets[i] = taint.clone();
        }
        self
    }

    /// Broadcast the empty taint set over this vector, modifying it in place. Java: `TaintVec
    /// setEmpties()`.
    pub fn set_empties(&mut self) -> &mut Self {
        self.set_copies(TaintSet::default())
    }

    /// Fill this vector as in [`TaintVec::array`], modifying it in place. Java: `TaintVec
    /// setArray(String name, long start)`.
    pub fn set_array(&mut self, name: &str, start: i64) -> &mut Self {
        for i in 0..self.length {
            self.sets[i] =
                TaintSet::of([TaintMark::new(format!("{}_{}", name, start + i as i64), std::iter::empty::<String>())]);
        }
        self
    }

    /// Modify the vector so each element becomes the union of itself and all elements of lesser
    /// significance.
    ///
    /// This should be used after [`TaintVec::zip_union`] to model operations with carries.
    ///
    /// Java: `TaintVec setCascade(boolean isBigEndian)`.
    pub fn set_cascade(&mut self, is_big_endian: bool) -> &mut Self {
        if is_big_endian {
            let mut i = self.length as isize - 2;
            while i >= 0 {
                let idx = i as usize;
                self.sets[idx] = self.sets[idx].union(&self.sets[idx + 1]);
                i -= 1;
            }
        }
        for i in 0..self.length.saturating_sub(1) {
            self.sets[i + 1] = self.sets[i + 1].union(&self.sets[i]);
        }
        self
    }

    /// Modify the vector so each element becomes the union of itself and its neighbor.
    ///
    /// This should be used to model shift operations. Both the shift direction and the
    /// endianness must be considered.
    ///
    /// Java: `TaintVec setBlur(boolean right)`.
    pub fn set_blur(&mut self, right: bool) -> &mut Self {
        if right {
            let mut i = self.length as isize - 2;
            while i >= 0 {
                let idx = i as usize;
                self.sets[idx + 1] = self.sets[idx + 1].union(&self.sets[idx]);
                i -= 1;
            }
        }
        for i in 0..self.length.saturating_sub(1) {
            self.sets[i] = self.sets[i].union(&self.sets[i + 1]);
        }
        self
    }

    /// Shift this vector some number of elements, in place.
    ///
    /// # Faithfully-preserved quirks
    ///
    /// This loop mutates `sets[i]` while reading `sets[src]` in the same forward pass, which
    /// Java does too, and which produces some surprising results faithfully reproduced here (see
    /// the dedicated tests below for worked examples):
    /// * For `right >= 0` (a rightward shift) with [`ShiftMode::Unbounded`] or
    ///   [`ShiftMode::Remainder`], the loop's first iteration always computes a negative `src`
    ///   and immediately breaks, so the vector comes back completely **unchanged** rather than
    ///   shifted.
    /// * For `right < 0` (a leftward shift), the loop breaks just before it would write the
    ///   final index, so that slot keeps its **original, stale** value instead of being emptied
    ///   as the class's own docstring diagram implies.
    /// * For [`ShiftMode::Circular`] with `right >= 0`, `adjustSrc` wraps a negative `src` back
    ///   into range instead of leaving it negative, so the loop does not break early -- but it
    ///   still reads an index it may have *already overwritten* earlier in the same pass, so a
    ///   wrapped-in value cascades forward into later slots instead of rotating cleanly.
    ///
    /// Java: `TaintVec setShifted(int right, ShiftMode mode)`.
    pub fn set_shifted(&mut self, right: i32, mode: ShiftMode) -> &mut Self {
        let length = self.length as i32;
        let right = mode.adjust_right(right, length);
        if right > length || -right > length {
            return self.set_empties();
        }
        if right < 0 {
            let start = self.sets[0].clone();
            for i in 0..self.length {
                let src = mode.adjust_src(i as i32 - right, length);
                if src < 0 || src >= length {
                    break;
                }
                self.sets[i] = if src == 0 { start.clone() } else { self.sets[src as usize].clone() };
            }
        }
        else {
            let start = self.sets[self.length - 1].clone();
            for i in 0..self.length.saturating_sub(1) {
                let src = mode.adjust_src(i as i32 - right, length);
                if src < 0 || src >= length {
                    break;
                }
                self.sets[i] =
                    if src == length - 1 { start.clone() } else { self.sets[src as usize].clone() };
            }
        }
        self
    }

    /// Drop all but `length` elements from this vector, creating a new vector.
    ///
    /// Drops the most significant elements of this vector, as specified by the endianness.
    ///
    /// # Panics
    /// Panics if `length` is greater than this vector's length, mirroring Java's
    /// `IllegalArgumentException`.
    ///
    /// Java: `TaintVec truncated(int length, boolean isBigEndian)`.
    pub fn truncated(&self, length: usize, is_big_endian: bool) -> TaintVec {
        if length > self.length {
            panic!("length must not exceed this vector's length");
        }
        let mut vec = TaintVec::new(length);
        let shift = if is_big_endian { self.length - length } else { 0 };
        for i in 0..length {
            vec.sets[i] = self.sets[i + shift].clone();
        }
        vec
    }

    /// Create a copy of this vector. Java: `copy()`.
    pub fn copy(&self) -> TaintVec {
        let mut vec = TaintVec::new(self.length);
        for i in 0..self.length {
            vec.sets[i] = self.sets[i].clone();
        }
        vec
    }

    /// Extend this vector to create a new vector of the given length.
    ///
    /// Elements are appended at the most significant end, as specified by the endianness. If
    /// signed, the appended elements are copies of the most significant element in this vector.
    /// Otherwise, they are empty taint sets.
    ///
    /// Java: `TaintVec extended(int length, boolean isBigEndian, boolean isSigned)`.
    pub fn extended(&self, length: usize, is_big_endian: bool, is_signed: bool) -> TaintVec {
        if length < self.length {
            return self.truncated(length, is_big_endian);
        }
        let mut vec = TaintVec::new(length);
        let diff = length - self.length;
        let shift = if is_big_endian { diff } else { 0 };
        for i in 0..self.length {
            vec.sets[i + shift] = self.sets[i].clone();
        }
        let ext = if is_signed {
            if is_big_endian { self.sets[0].clone() } else { self.sets[self.length - 1].clone() }
        }
        else {
            TaintSet::default()
        };
        let start = if is_big_endian { 0 } else { self.length };
        for i in 0..diff {
            vec.sets[start + i] = ext.clone();
        }
        vec
    }

    /// Extract a subpiece of this vector. Java: `TaintVec sub(int offset, int length)`.
    pub fn sub(&self, offset: usize, length: usize) -> TaintVec {
        let mut vec = TaintVec::new(length);
        for i in 0..length {
            vec.sets[i] = self.sets[i + offset].clone();
        }
        vec
    }

    /// The originating op. Java: `getOriginatingOp()`.
    pub fn get_originating_op(&self) -> Option<&PcodeOp> {
        self.originating_op.as_ref()
    }

    /// Supply the originating op.
    ///
    /// See the [module docs](self) for how this deviates from Java's `withOp`, which aliases the
    /// same backing array rather than copying it.
    ///
    /// Java: `TaintVec withOp(PcodeOp op)`.
    pub fn with_op(&self, op: PcodeOp) -> TaintVec {
        TaintVec::from_sets(self.sets.clone(), Some(op))
    }
}

impl fmt::Display for TaintVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<TaintVec: {}>", self.to_display())
    }
}

impl PartialEq for TaintVec {
    /// Java: `equals(Object)`, which compares only the list of sets (not the originating op).
    fn eq(&self, other: &Self) -> bool {
        self.sets == other.sets
    }
}

impl Eq for TaintVec {}

impl std::hash::Hash for TaintVec {
    /// Java: `hashCode()`, which hashes only the list of sets (not the originating op).
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.sets.hash(state);
    }
}

/// Common shifting behaviors. Java: the nested enum `TaintVec.ShiftMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftMode {
    /// No bound is applied to the shift. Values that fall off the edge are dropped. Furthermore,
    /// if the shift is greater than the length, all the values will fall off the edge and be
    /// dropped.
    ///
    /// ```text
    /// +---+------+
    /// | 0 | 1234 |
    /// | 1 | _123 |
    /// | 2 | __12 |
    /// | 3 | ___1 |
    /// | 4 | ____ |
    /// +---+------+
    /// ```
    Unbounded,
    /// Only the lowest required bits are taken for the shift amount, i.e., the remainder when
    /// divided by the length, often a power of 2. Values that fall off the edge are dropped.
    ///
    /// ```text
    /// +---+------+
    /// | 0 | 1234 |
    /// | 1 | _123 |
    /// | 2 | __12 |
    /// | 3 | ___1 |
    /// | 4 | 1234 | (Only the lowest 2 bits of the shift amount are considered)
    /// +---+------+
    /// ```
    Remainder,
    /// Only the lowest required bits are taken for the shift amount, i.e., the remainder when
    /// divided by the length, often a power of 2. (Even if unbounded, a circular shift yields the
    /// same result.) Values that fall off the edge are cycled to the opposite end.
    ///
    /// ```text
    /// +---+------+
    /// | 0 | 1234 |
    /// | 1 | 4123 |
    /// | 2 | 3412 |
    /// | 3 | 2341 |
    /// | 4 | 1234 |
    /// +---+------+
    /// ```
    Circular,
}

impl ShiftMode {
    fn adjust_right(&self, right: i32, length: i32) -> i32 {
        match self {
            ShiftMode::Unbounded => right,
            ShiftMode::Remainder | ShiftMode::Circular => right % length,
        }
    }

    fn adjust_src(&self, src: i32, length: i32) -> i32 {
        match self {
            ShiftMode::Unbounded | ShiftMode::Remainder => src,
            ShiftMode::Circular => {
                let temp = src % length;
                if temp < 0 { temp + length } else { temp }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(name: &str) -> TaintSet {
        TaintSet::of([TaintMark::new(name, std::iter::empty::<String>())])
    }

    fn op() -> PcodeOp {
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
        use crate::program::model::pcode::{OpCode, SequenceNumber};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        PcodeOp::new(OpCode::Copy, SequenceNumber::new(addr, 0), vec![], None)
    }

    #[test]
    fn new_is_all_empty_sets() {
        let v = TaintVec::new(3);
        assert_eq!(v.length, 3);
        for i in 0..3 {
            assert!(v.get(i).is_empty());
        }
        assert!(v.get_originating_op().is_none());
    }

    #[test]
    fn new_with_op_stores_the_op() {
        let v = TaintVec::new_with_op(2, op());
        assert!(v.get_originating_op().is_some());
    }

    #[test]
    fn of_builds_from_explicit_sets() {
        let v = TaintVec::of(op(), vec![mark("a"), mark("b")]);
        assert_eq!(v.length, 2);
        assert_eq!(v.get(0), &mark("a"));
        assert_eq!(v.get(1), &mark("b"));
    }

    #[test]
    fn empties_and_copies() {
        let e = TaintVec::empties(3);
        assert!(e.get(0).is_empty());
        assert!(e.get(2).is_empty());

        let c = TaintVec::copies(mark("x"), 3);
        for i in 0..3 {
            assert_eq!(c.get(i), &mark("x"));
        }
    }

    #[test]
    fn array_names_each_element_distinctly() {
        let v = TaintVec::array("arr", 0, 4);
        assert_eq!(v.to_display(), "[arr_0][arr_1][arr_2][arr_3]");
    }

    #[test]
    fn array_honors_a_nonzero_start() {
        let v = TaintVec::array("b", 10, 2);
        assert_eq!(v.to_display(), "[b_10][b_11]");
    }

    #[test]
    fn to_display_and_to_string() {
        let v = TaintVec::of(op(), vec![mark("a"), TaintSet::default()]);
        assert_eq!(v.to_display(), "[a][]");
        assert_eq!(v.to_string(), "<TaintVec: [a][]>");
    }

    #[test]
    fn equality_ignores_the_originating_op() {
        let a = TaintVec::of(op(), vec![mark("a")]);
        let b = TaintVec::new(1);
        let mut b = b;
        b.set(0, mark("a"));
        assert_eq!(a, b);
    }

    #[test]
    fn equality_considers_sets() {
        let a = TaintVec::of(op(), vec![mark("a")]);
        let b = TaintVec::of(op(), vec![mark("b")]);
        assert_ne!(a, b);
    }

    #[test]
    fn get_sets_returns_all_elements_in_order() {
        let v = TaintVec::of(op(), vec![mark("a"), mark("b")]);
        assert_eq!(v.get_sets(), &[mark("a"), mark("b")]);
    }

    #[test]
    fn set_replaces_one_element() {
        let mut v = TaintVec::new(2);
        v.set(1, mark("x"));
        assert!(v.get(0).is_empty());
        assert_eq!(v.get(1), &mark("x"));
    }

    #[test]
    fn set_range_copies_the_source_vector_at_the_start_index() {
        let mut v = TaintVec::new(4);
        let src = TaintVec::of(op(), vec![mark("a"), mark("b")]);
        v.set_range(1, &src);
        assert!(v.get(0).is_empty());
        assert_eq!(v.get(1), &mark("a"));
        assert_eq!(v.get(2), &mark("b"));
        assert!(v.get(3).is_empty());
    }

    #[test]
    fn zip_union_combines_same_indexed_elements() {
        let a = TaintVec::of(op(), vec![mark("a"), mark("b")]);
        let b = TaintVec::of(op(), vec![mark("c"), TaintSet::default()]);
        let z = a.zip_union(&b);
        assert_eq!(z.get(0), &a.get(0).union(&b.get(0)));
        assert_eq!(z.get(1), &mark("b"));
    }

    #[test]
    #[should_panic(expected = "must match in length")]
    fn zip_union_requires_matching_lengths() {
        let a = TaintVec::new(2);
        let b = TaintVec::new(3);
        a.zip_union(&b);
    }

    #[test]
    fn each_union_broadcasts_a_set_over_the_vector() {
        let a = TaintVec::of(op(), vec![mark("a"), mark("b")]);
        let u = a.each_union(&mark("z"));
        assert_eq!(u.get(0), &mark("a").union(&mark("z")));
        assert_eq!(u.get(1), &mark("b").union(&mark("z")));
    }

    #[test]
    fn union_reduces_the_whole_vector() {
        let v = TaintVec::of(op(), vec![mark("a"), mark("b"), TaintSet::default()]);
        let u = v.union();
        assert!(u.marks().contains(&TaintMark::new("a", std::iter::empty::<String>())));
        assert!(u.marks().contains(&TaintMark::new("b", std::iter::empty::<String>())));
        assert_eq!(u.marks().len(), 2);
    }

    #[test]
    fn tag_indirect_read_tags_the_offset_union_and_unions_with_each_element() {
        let bytes = TaintVec::of(op(), vec![mark("byte0"), mark("byte1")]);
        let offset = TaintVec::of(op(), vec![mark("off0"), mark("off1")]);
        let tagged = bytes.tag_indirect_read(&offset);
        let expected_tag = offset.union().tagged("indR");
        assert_eq!(tagged.get(0), &mark("byte0").union(&expected_tag));
        assert_eq!(tagged.get(1), &mark("byte1").union(&expected_tag));
    }

    #[test]
    fn tag_indirect_write_uses_the_indw_tag() {
        let bytes = TaintVec::of(op(), vec![mark("byte0")]);
        let offset = TaintVec::of(op(), vec![mark("off0")]);
        let tagged = bytes.tag_indirect_write(&offset);
        let expected_tag = offset.union().tagged("indW");
        assert_eq!(tagged.get(0), &mark("byte0").union(&expected_tag));
    }

    #[test]
    fn set_copies_and_set_empties_broadcast_in_place() {
        let mut v = TaintVec::of(op(), vec![mark("a"), mark("b")]);
        v.set_copies(mark("z"));
        assert_eq!(v.get(0), &mark("z"));
        assert_eq!(v.get(1), &mark("z"));

        v.set_empties();
        assert!(v.get(0).is_empty());
        assert!(v.get(1).is_empty());
    }

    #[test]
    fn set_array_fills_in_place() {
        let mut v = TaintVec::new(3);
        v.set_array("x", 5);
        assert_eq!(v.to_display(), "[x_5][x_6][x_7]");
    }

    #[test]
    fn set_cascade_little_endian_unions_forward() {
        // Little-endian: index 0 is least significant; cascade unions each element into the
        // next-more-significant one, so element i picks up everything from 0..=i.
        let mut v = TaintVec::of(op(), vec![mark("a"), mark("b"), mark("c")]);
        v.set_cascade(false);
        assert_eq!(v.get(0), &mark("a"));
        assert_eq!(v.get(1), &mark("a").union(&mark("b")));
        assert_eq!(v.get(2), &mark("a").union(&mark("b")).union(&mark("c")));
    }

    #[test]
    fn set_cascade_big_endian_first_folds_backward_then_forward() {
        let mut v = TaintVec::of(op(), vec![mark("a"), mark("b"), mark("c")]);
        v.set_cascade(true);
        // Backward pass (big-endian): sets[1] = b|c, sets[0] = a|(b|c).
        // Forward pass (always runs): sets[1] = (b|c)|sets[0], sets[2] = c|sets[1].
        let bc = mark("b").union(&mark("c"));
        let abc = mark("a").union(&bc);
        assert_eq!(v.get(0), &abc);
        assert_eq!(v.get(1), &bc.union(&abc));
        assert_eq!(v.get(2), &mark("c").union(&bc.union(&abc)));
    }

    #[test]
    fn set_blur_left_only_runs_the_backward_pass() {
        let mut v = TaintVec::of(op(), vec![mark("a"), mark("b"), mark("c")]);
        v.set_blur(false);
        // Only the forward pass runs: sets[i] = sets[i] | sets[i+1], right-to-left is skipped.
        assert_eq!(v.get(0), &mark("a").union(&mark("b")));
        assert_eq!(v.get(1), &mark("b").union(&mark("c")));
        assert_eq!(v.get(2), &mark("c"));
    }

    #[test]
    fn set_blur_right_runs_both_passes() {
        let mut v = TaintVec::of(op(), vec![mark("a"), mark("b"), mark("c")]);
        v.set_blur(true);
        // Backward pass: sets[2] = c|b, sets[1] = b|a.
        // Forward pass: sets[0] = a|(b|a), sets[1] = (b|a)|(c|b).
        let ba = mark("b").union(&mark("a"));
        let cb = mark("c").union(&mark("b"));
        assert_eq!(v.get(0), &mark("a").union(&ba));
        assert_eq!(v.get(1), &ba.union(&cb));
        assert_eq!(v.get(2), &cb);
    }

    #[test]
    fn set_shifted_positive_right_is_a_java_no_op_for_unbounded_and_remainder() {
        // Faithful to a real quirk in Java's `setShifted`: for `right >= 0` the forward loop
        // computes `src = i - right` starting at `i = 0`, which is negative whenever `right >= 1`
        // -- and since `adjustSrc` for UNBOUNDED/REMAINDER never wraps a negative `src` back into
        // range, the loop's very first `if (src < 0 ...) break;` fires immediately, so the loop
        // body never runs at all. The vector comes back completely unchanged, not shifted.
        let mut v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        v.set_shifted(1, ShiftMode::Unbounded);
        assert_eq!(v.to_display(), "[1][2][3][4]");
    }

    #[test]
    fn set_shifted_negative_left_leaves_a_stale_duplicate_at_the_vacated_end() {
        // Also faithful to Java: the `right < 0` loop runs `i` from `0` to `length - 1`
        // (inclusive of the last index) and breaks as soon as `src = i - right` reaches
        // `length`, which happens *before* writing that final index -- so the docstring's
        // "dropped" (emptied) high end is never actually cleared; it's left holding its
        // original, now-stale value, duplicated with its new neighbor.
        let mut v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        v.set_shifted(-1, ShiftMode::Unbounded);
        assert_eq!(v.to_display(), "[2][3][4][4]");
    }

    #[test]
    fn set_shifted_unbounded_beyond_length_empties_the_vector() {
        let mut v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        v.set_shifted(5, ShiftMode::Unbounded);
        assert_eq!(v.to_display(), "[][][][]");
    }

    #[test]
    fn set_shifted_remainder_wraps_the_amount_but_still_drops() {
        let mut v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        // 4 % 4 == 0, so a shift of the full length is a no-op under REMAINDER.
        v.set_shifted(4, ShiftMode::Remainder);
        assert_eq!(v.to_display(), "[1][2][3][4]");
    }

    #[test]
    fn set_shifted_circular_right_cascades_the_wrapped_value_forward() {
        // Faithful to a real quirk in Java: CIRCULAR's `adjustSrc` wraps a negative `src` back
        // into range instead of leaving it negative (unlike UNBOUNDED/REMAINDER), so this loop
        // does not break immediately the way the UNBOUNDED case above does -- but it still writes
        // `sets[i]` while reading `sets[src]` for `src < i` in the same forward pass, so each
        // freshly wrapped-in value (`"4"`, wrapped from the end to the front) gets copied forward
        // into every later slot too, rather than the "clean" rotation `[4][1][2][3]` the class's
        // own docstring diagram implies.
        let mut v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        v.set_shifted(1, ShiftMode::Circular);
        assert_eq!(v.to_display(), "[4][4][4][4]");
    }

    #[test]
    fn set_shifted_circular_left_rotates_the_other_way() {
        let mut v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        v.set_shifted(-1, ShiftMode::Circular);
        assert_eq!(v.to_display(), "[2][3][4][1]");
    }

    #[test]
    fn truncated_little_endian_keeps_the_low_end() {
        let v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        let t = v.truncated(2, false);
        assert_eq!(t.to_display(), "[1][2]");
    }

    #[test]
    fn truncated_big_endian_keeps_the_high_end() {
        let v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        let t = v.truncated(2, true);
        assert_eq!(t.to_display(), "[3][4]");
    }

    #[test]
    #[should_panic]
    fn truncated_rejects_a_longer_length() {
        let v = TaintVec::new(2);
        v.truncated(3, false);
    }

    #[test]
    fn copy_produces_an_independent_equal_vector() {
        let v = TaintVec::of(op(), vec![mark("a"), mark("b")]);
        let c = v.copy();
        assert_eq!(v, c);
    }

    #[test]
    fn extended_little_endian_unsigned_appends_empty_at_the_high_end() {
        let v = TaintVec::of(op(), vec![mark("1"), mark("2")]);
        let e = v.extended(4, false, false);
        assert_eq!(e.to_display(), "[1][2][][]");
    }

    #[test]
    fn extended_big_endian_unsigned_appends_empty_at_the_low_end() {
        let v = TaintVec::of(op(), vec![mark("1"), mark("2")]);
        let e = v.extended(4, true, false);
        assert_eq!(e.to_display(), "[][][1][2]");
    }

    #[test]
    fn extended_signed_replicates_the_most_significant_element() {
        let v = TaintVec::of(op(), vec![mark("1"), mark("2")]);
        // Little-endian: most-significant is the last element.
        let e = v.extended(4, false, true);
        assert_eq!(e.to_display(), "[1][2][2][2]");

        // Big-endian: most-significant is the first element.
        let e2 = v.extended(4, true, true);
        assert_eq!(e2.to_display(), "[1][1][1][2]");
    }

    #[test]
    fn extended_to_a_shorter_length_truncates_instead() {
        let v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        let e = v.extended(2, false, false);
        assert_eq!(e.to_display(), "[1][2]");
    }

    #[test]
    fn sub_extracts_a_subpiece() {
        let v = TaintVec::of(op(), vec![mark("1"), mark("2"), mark("3"), mark("4")]);
        let s = v.sub(1, 2);
        assert_eq!(s.to_display(), "[2][3]");
    }

    #[test]
    fn with_op_tags_a_copy_and_leaves_the_original_untagged() {
        let v = TaintVec::of(op(), vec![mark("a")]);
        let untagged = TaintVec::new(1);
        assert!(untagged.get_originating_op().is_none());

        let tagged = untagged.with_op(op());
        assert!(tagged.get_originating_op().is_some());
        assert!(untagged.get_originating_op().is_none());
        assert_eq!(tagged.get(0), untagged.get(0));
        let _ = v;
    }

    #[test]
    fn shift_mode_variants_are_distinct() {
        assert_ne!(ShiftMode::Unbounded, ShiftMode::Remainder);
        assert_ne!(ShiftMode::Remainder, ShiftMode::Circular);
        assert_ne!(ShiftMode::Unbounded, ShiftMode::Circular);
    }
}
