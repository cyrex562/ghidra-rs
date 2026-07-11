//! Models `ghidra.pcodeCPort.slghpatexpress.TokenPattern`.

use crate::decompiler::seam_stubs::Pattern;
use crate::sleigh::grammar::Location;

/// The token/context match pattern built up while parsing and combining sleigh pattern
/// expressions and constructors.
///
/// Models the concrete class `ghidra.pcodeCPort.slghpatexpress.TokenPattern`, exposed here as a
/// trait so that callers -- e.g. [`crate::decompiler::slghpatexpress::PatternValue::gen_pattern`]
/// -- do not need to depend on its full implementation, which is not yet ported.
pub trait TokenPattern: Send + Sync {
    /// The source location this pattern was constructed at.
    fn location(&self) -> &Location;

    /// The underlying mask/value pattern (stubbed as [`Pattern`] pending its own port).
    fn get_pattern(&self) -> &dyn Pattern;

    /// Whether this pattern matches every possible input.
    fn always_true(&self) -> bool;

    /// Whether this pattern never matches.
    fn always_false(&self) -> bool;

    /// Whether the instruction (non-context) portion of this pattern always matches.
    fn always_instruction_true(&self) -> bool;

    /// Whether tokens may extend past the left end of this pattern's token list.
    fn get_left_ellipsis(&self) -> bool;

    /// Whether tokens may extend past the right end of this pattern's token list.
    fn get_right_ellipsis(&self) -> bool;

    /// Sets whether tokens may extend past the left end of this pattern's token list.
    fn set_left_ellipsis(&mut self, val: bool);

    /// Sets whether tokens may extend past the right end of this pattern's token list.
    fn set_right_ellipsis(&mut self, val: bool);

    /// Total length, in bytes, of the concatenated tokens this pattern matches.
    fn get_minimum_length(&self) -> i32;

    /// Simplifies this pattern's underlying [`Pattern`] in place.
    fn simplify_pattern(&mut self);

    /// Replaces this pattern's contents with a simplified copy of `tokpat`.
    fn copy_into(&mut self, tokpat: &dyn TokenPattern);

    /// Returns `self` AND `tokpat`.
    fn do_and(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern>;

    /// Returns `self` OR `tokpat`.
    fn do_or(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern>;

    /// Returns the concatenation of `self` followed by `tokpat`.
    fn do_cat(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern>;

    /// Returns the most general pattern matched by both `self` and `tokpat`.
    fn common_sub_pattern(&self, tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial mock proving [`Pattern`] can back a [`TokenPattern`] implementation.
    struct MockPattern;
    impl Pattern for MockPattern {}

    /// Trivial mock proving `TokenPattern` is object-safe and usable behind `Box<dyn TokenPattern>`.
    struct MockTokenPattern {
        location: Location,
        pattern: Box<dyn Pattern>,
        left_ellipsis: bool,
        right_ellipsis: bool,
    }

    impl MockTokenPattern {
        fn new(location: Location) -> Self {
            Self {
                location,
                pattern: Box::new(MockPattern),
                left_ellipsis: false,
                right_ellipsis: false,
            }
        }
    }

    impl TokenPattern for MockTokenPattern {
        fn location(&self) -> &Location {
            &self.location
        }

        fn get_pattern(&self) -> &dyn Pattern {
            self.pattern.as_ref()
        }

        fn always_true(&self) -> bool {
            true
        }

        fn always_false(&self) -> bool {
            false
        }

        fn always_instruction_true(&self) -> bool {
            true
        }

        fn get_left_ellipsis(&self) -> bool {
            self.left_ellipsis
        }

        fn get_right_ellipsis(&self) -> bool {
            self.right_ellipsis
        }

        fn set_left_ellipsis(&mut self, val: bool) {
            self.left_ellipsis = val;
        }

        fn set_right_ellipsis(&mut self, val: bool) {
            self.right_ellipsis = val;
        }

        fn get_minimum_length(&self) -> i32 {
            0
        }

        fn simplify_pattern(&mut self) {}

        fn copy_into(&mut self, tokpat: &dyn TokenPattern) {
            self.left_ellipsis = tokpat.get_left_ellipsis();
            self.right_ellipsis = tokpat.get_right_ellipsis();
        }

        fn do_and(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }

        fn do_or(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }

        fn do_cat(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }

        fn common_sub_pattern(&self, _tokpat: &dyn TokenPattern) -> Box<dyn TokenPattern> {
            Box::new(MockTokenPattern::new(self.location.clone()))
        }
    }

    #[test]
    fn object_safe_and_ellipsis_roundtrip() {
        let mut tp: Box<dyn TokenPattern> =
            Box::new(MockTokenPattern::new(Location::new("test.sleigh", 1)));
        assert!(!tp.get_left_ellipsis());
        tp.set_left_ellipsis(true);
        assert!(tp.get_left_ellipsis());
    }

    #[test]
    fn do_and_combines_via_trait_object() {
        let a: Box<dyn TokenPattern> =
            Box::new(MockTokenPattern::new(Location::new("test.sleigh", 1)));
        let b = MockTokenPattern::new(Location::new("test.sleigh", 2));
        let combined = a.do_and(&b);
        assert!(combined.always_true());
    }

    #[test]
    fn copy_into_copies_ellipses() {
        let mut a = MockTokenPattern::new(Location::new("test.sleigh", 1));
        let mut b = MockTokenPattern::new(Location::new("test.sleigh", 2));
        b.set_left_ellipsis(true);
        b.set_right_ellipsis(true);
        a.copy_into(&b);
        assert!(a.get_left_ellipsis());
        assert!(a.get_right_ellipsis());
    }
}
