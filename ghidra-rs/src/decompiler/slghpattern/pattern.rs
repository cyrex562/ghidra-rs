//! Models `ghidra.pcodeCPort.slghpattern.Pattern`.
//!
//! # Promotion note
//!
//! This was a `seam_stubs.rs` placeholder (`pub trait Pattern: Send + Sync {}`) that
//! [`DisjointPattern`](super::DisjointPattern) and [`OrPattern`](super::OrPattern) were built
//! against before this class had its own port. Because `Pattern` had no real methods yet, both
//! of those subtraits had to redeclare the whole abstract surface themselves to be useful.
//! Promoting `Pattern` for real moves that surface up here; `DisjointPattern` and `OrPattern`
//! were both edited in this same change to stop redeclaring it (Rust doesn't merge two
//! same-named trait items from a supertrait and a subtrait the way Java overriding does -- they
//! would otherwise become two distinct, ambiguous methods).

use std::io;

use crate::decompiler::slghpattern::DisjointPattern;
use crate::program::model::pcode::Encoder;

/// The base pattern type: something that can be matched against an instruction/context, and
/// combined with other patterns via AND/OR/simplification.
///
/// Models the abstract class `ghidra.pcodeCPort.slghpattern.Pattern`.
pub trait Pattern: Send + Sync {
    /// Releases any resources held by this pattern. No-op by default, matching Java's
    /// non-abstract `dispose()`.
    fn dispose(&mut self) {}

    /// Returns a simplified clone of this pattern.
    fn simplify_clone(&self) -> Box<dyn Pattern>;

    /// Shifts the instruction-bit portion of this pattern by `sa`.
    fn shift_instruction(&mut self, sa: i32);

    /// ORs this pattern with `b`.
    fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// ANDs this pattern with `b`.
    fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// The common sub-pattern shared by this pattern and `b`.
    fn common_sub_pattern(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// The number of disjuncts making up this pattern.
    ///
    /// Defaults to `0`, matching `DisjointPattern`'s override (a plain disjoint pattern has no
    /// sub-disjuncts); [`OrPattern`](super::OrPattern) implementors override this to reflect
    /// their disjunct list.
    fn num_disjoint(&self) -> i32 {
        0
    }

    /// The `i`th disjunct, or `None` if out of range.
    ///
    /// Defaults to `None`, matching `DisjointPattern`'s override;
    /// [`OrPattern`](super::OrPattern) implementors override this.
    fn get_disjoint(&self, _i: i32) -> Option<&dyn DisjointPattern> {
        None
    }

    /// Whether this pattern always matches.
    fn always_true(&self) -> bool;

    /// Whether this pattern never matches.
    fn always_false(&self) -> bool;

    /// Whether this pattern's instruction portion always matches.
    fn always_instruction_true(&self) -> bool;

    /// Encodes this pattern to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal concrete pattern proving the trait is object-safe and its defaults behave like
    /// Java's `DisjointPattern` override (0 disjuncts, no `i`th disjunct).
    struct MockPattern {
        is_true: bool,
    }

    impl Pattern for MockPattern {
        fn simplify_clone(&self) -> Box<dyn Pattern> {
            Box::new(MockPattern { is_true: self.is_true })
        }

        fn shift_instruction(&mut self, _sa: i32) {}

        fn do_or(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            Box::new(MockPattern { is_true: true })
        }

        fn do_and(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            Box::new(MockPattern { is_true: false })
        }

        fn common_sub_pattern(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            Box::new(MockPattern { is_true: false })
        }

        fn always_true(&self) -> bool {
            self.is_true
        }

        fn always_false(&self) -> bool {
            !self.is_true
        }

        fn always_instruction_true(&self) -> bool {
            self.is_true
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn num_disjoint_and_get_disjoint_default_to_the_disjoint_pattern_case() {
        let p = MockPattern { is_true: true };
        assert_eq!(p.num_disjoint(), 0);
        assert!(p.get_disjoint(0).is_none());
    }

    #[test]
    fn dispose_defaults_to_a_no_op() {
        let mut p = MockPattern { is_true: true };
        p.dispose(); // must not panic
    }

    #[test]
    fn always_true_and_always_false_are_consistent_for_the_mock() {
        let t = MockPattern { is_true: true };
        let f = MockPattern { is_true: false };
        assert!(t.always_true());
        assert!(!t.always_false());
        assert!(!f.always_true());
        assert!(f.always_false());
    }

    #[test]
    fn simplify_clone_preserves_truth_value() {
        let p = MockPattern { is_true: true };
        let cloned = p.simplify_clone();
        assert!(cloned.always_true());
    }

    #[test]
    fn trait_object_is_usable_through_box_dyn_pattern() {
        let p: Box<dyn Pattern> = Box::new(MockPattern { is_true: true });
        assert!(p.always_true());
    }
}
