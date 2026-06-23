use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use super::TaintMark;

/// An immutable set of multiple taint marks.
///
/// A variable in an emulator could be tainted by multiple marks, so we must
/// use vectors of sets, not vectors of marks. Two sets are equal when they
/// contain exactly the same marks (see [`TaintMark`]'s equality semantics).
#[derive(Clone, Debug)]
pub struct TaintSet {
    marks: HashSet<TaintMark>,
    /// Cached hash: commutative sum of element hashes, consistent with `PartialEq`.
    hash: u64,
}

impl TaintSet {
    fn from_set(marks: HashSet<TaintMark>) -> Self {
        let hash = Self::compute_hash(&marks);
        Self { marks, hash }
    }

    /// Commutative (order-independent) hash over all marks, mirrors Java's
    /// `HashSet.hashCode()` which sums element hash codes.
    fn compute_hash(marks: &HashSet<TaintMark>) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        marks.iter().fold(0u64, |acc, m| {
            let mut h = DefaultHasher::new();
            m.hash(&mut h);
            acc.wrapping_add(h.finish())
        })
    }

    /// Parse a semicolon-separated list of taint marks.
    ///
    /// Form: `myVar:tag1,tag2;anotherVar;yetAnother`.
    pub fn parse(s: &str) -> Self {
        let marks: HashSet<TaintMark> = s.split(';').map(TaintMark::parse).collect();
        Self::from_set(marks)
    }

    /// Create a taint set from the given marks.
    pub fn of(marks: impl IntoIterator<Item = TaintMark>) -> Self {
        Self::from_set(marks.into_iter().collect())
    }

    /// Get the marks in this set.
    pub fn marks(&self) -> &HashSet<TaintMark> {
        &self.marks
    }

    /// Check if this set is empty.
    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    /// Return the union of this set and `other`.
    pub fn union(&self, other: &TaintSet) -> TaintSet {
        let mut marks = self.marks.clone();
        marks.extend(other.marks.iter().cloned());
        Self::from_set(marks)
    }

    /// Return a new set with every mark tagged with `tag`.
    pub fn tagged(&self, tag: &str) -> TaintSet {
        let marks: HashSet<TaintMark> = self.marks.iter().map(|m| m.tagged(tag)).collect();
        Self::from_set(marks)
    }
}

impl Default for TaintSet {
    /// Returns the empty set — the default for all state variables.
    fn default() -> Self {
        Self::from_set(HashSet::new())
    }
}

impl std::fmt::Display for TaintSet {
    /// Semicolon-separated list of mark strings; see [`TaintSet::parse`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<String> = self.marks.iter().map(|m| m.to_string()).collect();
        parts.sort_unstable(); // deterministic output
        write!(f, "{}", parts.join(";"))
    }
}

impl PartialEq for TaintSet {
    fn eq(&self, other: &Self) -> bool {
        self.marks == other.marks
    }
}

impl Eq for TaintSet {}

impl Hash for TaintSet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(s: &str) -> TaintMark {
        TaintMark::parse(s)
    }

    #[test]
    fn default_is_empty() {
        let s = TaintSet::default();
        assert!(s.is_empty());
        assert_eq!(s.marks().len(), 0);
    }

    #[test]
    fn of_single_mark() {
        let s = TaintSet::of([mark("foo")]);
        assert!(!s.is_empty());
        assert!(s.marks().contains(&mark("foo")));
    }

    #[test]
    fn of_deduplicates() {
        let s = TaintSet::of([mark("foo"), mark("foo")]);
        assert_eq!(s.marks().len(), 1);
    }

    #[test]
    fn parse_single() {
        let s = TaintSet::parse("myVar");
        assert_eq!(s.marks().len(), 1);
        assert!(s.marks().contains(&mark("myVar")));
    }

    #[test]
    fn parse_multiple() {
        let s = TaintSet::parse("myVar:tag1,tag2;anotherVar;yetAnother");
        assert_eq!(s.marks().len(), 3);
        assert!(s.marks().contains(&mark("myVar:tag1,tag2")));
        assert!(s.marks().contains(&mark("anotherVar")));
        assert!(s.marks().contains(&mark("yetAnother")));
    }

    #[test]
    fn to_string_round_trip_single() {
        let original = TaintSet::of([mark("foo:a,b")]);
        let s = original.to_string();
        let parsed = TaintSet::parse(&s);
        assert_eq!(original, parsed);
    }

    #[test]
    fn to_string_round_trip_multi() {
        let original = TaintSet::of([mark("foo"), mark("bar:x"), mark("baz:y,z")]);
        let s = original.to_string();
        let parsed = TaintSet::parse(&s);
        assert_eq!(original, parsed);
    }

    #[test]
    fn equality_same_marks() {
        let a = TaintSet::of([mark("x"), mark("y")]);
        let b = TaintSet::of([mark("y"), mark("x")]);
        assert_eq!(a, b);
    }

    #[test]
    fn equality_different_marks() {
        let a = TaintSet::of([mark("x")]);
        let b = TaintSet::of([mark("y")]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_equal_sets_same_hash() {
        use std::collections::hash_map::DefaultHasher;
        let a = TaintSet::of([mark("x"), mark("y")]);
        let b = TaintSet::of([mark("y"), mark("x")]);
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn union_combines_marks() {
        let a = TaintSet::of([mark("x")]);
        let b = TaintSet::of([mark("y")]);
        let u = a.union(&b);
        assert_eq!(u.marks().len(), 2);
        assert!(u.marks().contains(&mark("x")));
        assert!(u.marks().contains(&mark("y")));
    }

    #[test]
    fn union_deduplicates() {
        let a = TaintSet::of([mark("x"), mark("y")]);
        let b = TaintSet::of([mark("y"), mark("z")]);
        let u = a.union(&b);
        assert_eq!(u.marks().len(), 3);
    }

    #[test]
    fn union_with_empty() {
        let a = TaintSet::of([mark("x")]);
        let empty = TaintSet::default();
        assert_eq!(a.union(&empty), a);
        assert_eq!(empty.union(&a), a);
    }

    #[test]
    fn tagged_adds_tag_to_all_marks() {
        let s = TaintSet::of([mark("a"), mark("b:existing")]);
        let t = s.tagged("indirect");
        assert_eq!(t.marks().len(), 2);
        assert!(t.marks().contains(&mark("a:indirect")));
        assert!(t.marks().contains(&mark("b:existing,indirect")));
    }

    #[test]
    fn tagged_empty_set_stays_empty() {
        let s = TaintSet::default();
        let t = s.tagged("x");
        assert!(t.is_empty());
    }

    #[test]
    fn can_be_used_in_hashset() {
        let mut set = std::collections::HashSet::new();
        set.insert(TaintSet::of([mark("a")]));
        set.insert(TaintSet::of([mark("a")]));
        set.insert(TaintSet::of([mark("b")]));
        assert_eq!(set.len(), 2);
    }
}
