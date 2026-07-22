//! Models `ghidra.pcodeCPort.slghsymbol.FamilySymbol`.

use crate::decompiler::slghpatexpress::PatternValue;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;

/// A [`TripleSymbol`] that resolves to a family of related pattern values.
///
/// This is an abstract type that serves as the base for symbols whose pattern matching is
/// driven by a single backing [`PatternValue`] (e.g. context fields, token fields, or lookup
/// tables keyed by such a value).
///
/// Models the abstract class `ghidra.pcodeCPort.slghsymbol.FamilySymbol`, which extends
/// `TripleSymbol`.
pub trait FamilySymbol: TripleSymbol {
    /// Gets the pattern value backing this symbol.
    ///
    /// Subclasses must implement this to expose the pattern value used to resolve the family.
    fn get_pattern_value(&self) -> &dyn PatternValue;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::seam_stubs::PatternExpression;
    use crate::decompiler::utils::MutableInt;
    use crate::sleigh::grammar::Location;

    struct MockTokenPattern {
        location: Location,
        pattern: Box<dyn crate::decompiler::seam_stubs::Pattern>,
        left_ellipsis: bool,
        right_ellipsis: bool,
    }

    impl MockTokenPattern {
        fn new() -> Self {
            Self {
                location: Location::new("test.sleigh", 1),
                pattern: Box::new(MockPattern),
                left_ellipsis: false,
                right_ellipsis: false,
            }
        }
    }

    struct MockPattern;
    impl crate::decompiler::seam_stubs::Pattern for MockPattern {}

    impl crate::decompiler::slghpatexpress::TokenPattern for MockTokenPattern {
        fn location(&self) -> &Location {
            &self.location
        }

        fn get_pattern(&self) -> &dyn crate::decompiler::seam_stubs::Pattern {
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

        fn copy_into(&mut self, tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern) {
            self.left_ellipsis = tokpat.get_left_ellipsis();
            self.right_ellipsis = tokpat.get_right_ellipsis();
        }

        fn do_and(
            &self,
            _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern,
        ) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> {
            Box::new(MockTokenPattern::new())
        }

        fn do_or(
            &self,
            _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern,
        ) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> {
            Box::new(MockTokenPattern::new())
        }

        fn do_cat(
            &self,
            _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern,
        ) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> {
            Box::new(MockTokenPattern::new())
        }

        fn common_sub_pattern(
            &self,
            _tokpat: &dyn crate::decompiler::slghpatexpress::TokenPattern,
        ) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> {
            Box::new(MockTokenPattern::new())
        }
    }

    /// A fixed pattern value in the range `[min, max]`, standing in for a real context/token
    /// field for the purposes of exercising the `FamilySymbol` seam.
    struct FixedValue {
        min: i64,
        max: i64,
    }

    impl PatternExpression for FixedValue {}

    impl PatternValue for FixedValue {
        fn gen_pattern(&self, _val: i64) -> Box<dyn crate::decompiler::slghpatexpress::TokenPattern> {
            Box::new(MockTokenPattern::new())
        }

        fn min_value(&self) -> i64 {
            self.min
        }

        fn max_value(&self) -> i64 {
            self.max
        }
    }

    /// A minimal `FamilySymbol` implementation backed by a single `FixedValue`, mirroring how
    /// concrete SLEIGH symbols (context fields, token fields) resolve to a pattern value.
    struct TestFamilySymbol {
        patval: FixedValue,
    }

    impl TripleSymbol for TestFamilySymbol {
        fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
            Box::new(FixedValue {
                min: self.patval.min,
                max: self.patval.max,
            })
        }
    }

    impl FamilySymbol for TestFamilySymbol {
        fn get_pattern_value(&self) -> &dyn PatternValue {
            &self.patval
        }
    }

    #[test]
    fn get_pattern_value_exposes_backing_value() {
        let symbol = TestFamilySymbol {
            patval: FixedValue { min: 2, max: 9 },
        };
        let dyn_symbol: &dyn FamilySymbol = &symbol;
        let value = dyn_symbol.get_pattern_value();
        assert_eq!(value.min_value(), 2);
        assert_eq!(value.max_value(), 9);
    }

    #[test]
    fn family_symbol_is_also_a_triple_symbol() {
        let symbol = TestFamilySymbol {
            patval: FixedValue { min: 0, max: 15 },
        };
        let dyn_symbol: &dyn FamilySymbol = &symbol;
        let _pattern_expr = dyn_symbol.get_pattern_expression();
        assert_eq!(dyn_symbol.get_size(), 0);
    }

    #[test]
    fn get_sub_value_reads_and_advances_listpos() {
        let symbol = TestFamilySymbol {
            patval: FixedValue { min: 0, max: 0 },
        };
        let value = symbol.get_pattern_value();
        let replace = vec![7, 8, 9];
        let mut listpos = MutableInt::new(0);
        let res = value.get_sub_value(&replace, &mut listpos);
        assert_eq!(res, 7);
        assert_eq!(listpos.get(), 1);
    }
}
