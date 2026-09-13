//! Port of `generic.lsh.vector.LSHCosineVectorAccum`.

use std::collections::BTreeSet;

use crate::generic::lsh::vector::lsh_cosine_vector::LSHCosineVector;
use crate::generic::lsh::vector::lsh_vector::LSHVector;
use crate::generic::lsh::vector::vector_compare::VectorCompare;
use crate::generic::lsh::vector::hash_entry::HashEntry;

/// A single (hash, weight) pair pending accumulation.
///
/// Port of the nested `LSHCosineVectorAccum.Entry` static class. Ordering and equality both
/// mirror Java's real (if arguably-buggy) `compareTo`/`equals`: **only `hash` participates**,
/// compared as an *unsigned* 32-bit integer (see `Entry.compareTo`'s doc comment: "Comparison
/// must be UNSIGNED!!"). Two entries with the same `hash` but different `weight` are therefore
/// indistinguishable to both this type's `Ord` and its `Eq` -- exactly matching the fact that
/// Java's `TreeSet<Entry>` (which orders and de-duplicates purely via `compareTo`, never
/// `equals`/`hashCode`) silently drops a second `addHash` call for an already-seen `hash`,
/// keeping whichever weight arrived first. [`BTreeSet::insert`] reproduces this for free: it
/// keeps the original element and drops the new one when an equal element is already present.
#[derive(Debug, Clone, Copy)]
struct Entry {
    hash: i32,
    weight: f64,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    /// Mirrors `Entry.compareTo`'s unsigned comparison of `hash`.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.hash as u32).cmp(&(other.hash as u32))
    }
}

/// A cosine vector where (feature, weight) pairs can be accumulated over time via
/// [`LSHCosineVectorAccum::add_hash`]. Once either [`LSHCosineVectorAccum::get_length`] or
/// [`LSHCosineVectorAccum::compare`] is called the vector becomes "finalized" and behaves as an
/// ordinary [`LSHCosineVector`].
///
/// Port of `generic.lsh.vector.LSHCosineVectorAccum`, which `extends LSHCosineVector`. Following
/// this crate's composition-over-inheritance convention, the inherited state is held in a `base:
/// LSHCosineVector` field instead of an (impossible) Rust inheritance relationship; use
/// [`LSHCosineVectorAccum::base`]/[`LSHCosineVectorAccum::base_mut`] to reach every inherited
/// (non-overridden) [`LSHCosineVector`]/[`LSHVector`] method (e.g. `save_xml`), exactly as Java
/// code can call any of those on an `LSHCosineVectorAccum` instance via ordinary inheritance.
///
/// # Deviations / preserved quirks
///
/// * **`numEntries()` panics after finalization.** Java's override is `return treehash.size();`
///   with no check of the `finalized` flag; since [`LSHCosineVectorAccum::do_finalize`] (like
///   Java's `doFinalize`) sets the backing collection to `null` once done ("Allow the accumulator
///   to be reclaimed"), a `numEntries()` call *after* finalization throws
///   `NullPointerException` in Java. This port reproduces that by storing `treehash` as
///   `Option<BTreeSet<Entry>>` and using `.expect(..)` in
///   [`LSHCosineVectorAccum::num_entries`], which panics the same way post-finalization --
///   faithfully preserved (see the dedicated test) rather than silently fixed by falling back to
///   `base.num_entries()`.
/// * **`compare` requires a compile-time `LSHCosineVectorAccum`, not just any `LSHVector`.**
///   Java's `compare(LSHVector op2, VectorCompare data)` declares the general `LSHVector`
///   interface type for `op2`, but its body immediately does `((LSHCosineVectorAccum)
///   op2).doFinalize()` -- a downcast that throws `ClassCastException` at runtime for any other
///   `LSHVector` implementor. This port makes that requirement a static one instead: `op2: &mut
///   LSHCosineVectorAccum`. This is strictly narrower at the type level but *never* rejects
///   anything Java would actually accept without throwing, and turns Java's runtime CCE into a
///   compile error -- consistent with (and for exactly the same underlying reason as) the
///   narrower deviation already documented on [`LSHCosineVector`]'s own `compare`/`compare_counts`
///   /`compare_detail` methods, which cannot downcast an arbitrary `T: LSHVector` back to
///   `LSHCosineVector` either.
/// * **`add_hash`/`get_length`/`compare` take `&mut self`.** Java's fields are mutated in place
///   with no synchronization concern at the language level; Rust's aliasing rules require `&mut
///   self` anywhere `do_finalize`'s internal mutation (`treehash` -> `None`, `base.hash`
///   populated) can be triggered.
pub struct LSHCosineVectorAccum {
    base: LSHCosineVector,
    treehash: Option<BTreeSet<Entry>>,
    finalized: bool,
}

impl LSHCosineVectorAccum {
    /// Creates a new, empty accumulator.
    ///
    /// Mirrors `LSHCosineVectorAccum()`.
    pub fn new() -> Self {
        Self { base: LSHCosineVector::new(), treehash: Some(BTreeSet::new()), finalized: false }
    }

    /// Accumulates one (hash, weight) pair.
    ///
    /// Mirrors `addHash(int, double)`.
    ///
    /// # Panics
    ///
    /// Panics if this accumulator has already been finalized (mirrors Java's `throw new
    /// RuntimeException("already finalized")`).
    pub fn add_hash(&mut self, h: i32, w: f64) {
        if self.finalized {
            panic!("already finalized");
        }
        self.treehash.as_mut().unwrap().insert(Entry { hash: h, weight: w });
    }

    /// Finalizes the accumulator: converts every accumulated (hash, weight) pair (in ascending,
    /// unsigned-hash order) into the base vector's [`HashEntry`] list, then discards the
    /// accumulation buffer. Idempotent: a second call is a no-op.
    ///
    /// Mirrors `doFinalize()`.
    pub fn do_finalize(&mut self) {
        if self.finalized {
            return;
        }
        let treehash = self.treehash.take().unwrap();
        let entries: Vec<HashEntry> = treehash
            .into_iter()
            .map(|entry| HashEntry::with_weight(entry.hash, 1, entry.weight))
            .collect();
        self.base.set_hash_entries(entries);
        self.finalized = true;
    }

    /// Finalizes (if not already) and returns the vector's Euclidean length.
    ///
    /// Mirrors the overridden `getLength()`.
    pub fn get_length(&mut self) -> f64 {
        self.do_finalize();
        self.base.get_length()
    }

    /// Finalizes both this accumulator and `op2`, then compares the two as ordinary
    /// [`LSHCosineVector`]s.
    ///
    /// Mirrors the overridden `compare(LSHVector, VectorCompare)`; see the struct docs for why
    /// `op2` is statically typed as `&mut LSHCosineVectorAccum` rather than a generic
    /// `LSHVector`.
    pub fn compare(&mut self, op2: &mut LSHCosineVectorAccum, data: &mut VectorCompare) -> f64 {
        self.do_finalize();
        op2.do_finalize();
        self.base.compare(&op2.base, data)
    }

    /// The number of (hash, weight) pairs accumulated so far.
    ///
    /// Mirrors the overridden `numEntries()`.
    ///
    /// # Panics
    ///
    /// Panics if called after finalization -- see the struct's own docs for why this faithfully
    /// reproduces a genuine Java `NullPointerException`.
    pub fn num_entries(&self) -> i32 {
        self.treehash
            .as_ref()
            .expect(
                "numEntries() called after finalization: Java's own numEntries() override reads \
                 the (by-then-nulled) treehash field unconditionally and throws \
                 NullPointerException here -- faithfully reproduced as a panic",
            )
            .len() as i32
    }

    /// Accesses the composed base [`LSHCosineVector`], through which every inherited (i.e.
    /// non-overridden in Java) method -- `save_xml`, `save_sql`, `calc_unique_hash`, etc. -- is
    /// reached, exactly as Java code can call them directly on an `LSHCosineVectorAccum`
    /// instance via ordinary inheritance.
    pub fn base(&self) -> &LSHCosineVector {
        &self.base
    }

    /// Mutable variant of [`LSHCosineVectorAccum::base`].
    pub fn base_mut(&mut self) -> &mut LSHCosineVector {
        &mut self.base
    }
}

impl Default for LSHCosineVectorAccum {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accumulator_is_empty() {
        let accum = LSHCosineVectorAccum::new();
        assert_eq!(accum.num_entries(), 0);
    }

    #[test]
    fn add_hash_accumulates_distinct_hashes() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(5, 1.0);
        accum.add_hash(9, 2.0);
        assert_eq!(accum.num_entries(), 2);
    }

    /// Faithful reproduction of the Java quirk documented on [`Entry`]: a duplicate `hash` is
    /// silently dropped (the *first* weight wins), because Java's `TreeSet<Entry>` de-duplicates
    /// via `compareTo` (hash-only), not `equals`.
    #[test]
    fn add_hash_with_a_duplicate_hash_keeps_the_first_weight() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(5, 1.0);
        accum.add_hash(5, 999.0); // silently dropped; hash 5 already present
        assert_eq!(accum.num_entries(), 1);

        let mut data = VectorCompare::new();
        let mut other = LSHCosineVectorAccum::new();
        other.add_hash(5, 1.0);
        let score = accum.compare(&mut other, &mut data);
        // If the second add_hash had overwritten the weight to 999.0, this dot product/score
        // would differ; it doesn't, proving the first weight (1.0) survived.
        assert_eq!(score, 1.0);
    }

    #[test]
    #[should_panic(expected = "already finalized")]
    fn add_hash_after_finalize_panics() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(1, 1.0);
        accum.do_finalize();
        accum.add_hash(2, 1.0);
    }

    #[test]
    fn do_finalize_is_idempotent() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(1, 3.0);
        accum.add_hash(2, 4.0);
        accum.do_finalize();
        let len_once = accum.base().get_length();
        accum.do_finalize(); // no-op
        assert_eq!(accum.base().get_length(), len_once);
    }

    #[test]
    fn get_length_finalizes_and_matches_a_plain_cosine_vector() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(1, 3.0);
        accum.add_hash(2, 4.0);
        assert_eq!(accum.get_length(), 5.0); // sqrt(3^2 + 4^2)
    }

    #[test]
    fn entries_are_finalized_in_ascending_unsigned_hash_order() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(-1, 1.0); // unsigned: 0xFFFFFFFF (large)
        accum.add_hash(1, 1.0); // unsigned: 1 (small)
        accum.add_hash(0, 1.0); // unsigned: 0 (smallest)
        accum.do_finalize();
        let entries = accum.base().get_entries();
        assert_eq!(entries[0].get_hash(), 0);
        assert_eq!(entries[1].get_hash(), 1);
        assert_eq!(entries[2].get_hash(), -1);
    }

    #[test]
    fn compare_finalizes_both_sides_and_matches_plain_vector_comparison() {
        let mut a = LSHCosineVectorAccum::new();
        a.add_hash(1, 3.0);
        a.add_hash(2, 4.0);
        let mut b = LSHCosineVectorAccum::new();
        b.add_hash(1, 3.0);
        b.add_hash(2, 4.0);

        let mut data = VectorCompare::new();
        let score = a.compare(&mut b, &mut data);
        assert_eq!(score, 1.0); // identical vectors -> perfect cosine similarity
        assert_eq!(data.dotproduct, 25.0);
    }

    /// Faithful reproduction of the Java quirk documented on the struct: `numEntries()` doesn't
    /// guard against having already been finalized, and panics (Java: NPE) rather than falling
    /// back to the base vector's entry count.
    #[test]
    #[should_panic(expected = "numEntries() called after finalization")]
    fn num_entries_after_finalize_panics() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(1, 1.0);
        accum.do_finalize();
        let _ = accum.num_entries();
    }

    #[test]
    fn base_accessor_reaches_inherited_lshvector_behavior() {
        let mut accum = LSHCosineVectorAccum::new();
        accum.add_hash(7, 1.0);
        accum.do_finalize();
        // `save_sql` is never overridden by LSHCosineVectorAccum in Java, so it's reached purely
        // through inheritance there; here it's reached through the composed `base()`.
        assert_eq!(accum.base().save_sql(), "(1:7)");
    }
}
