//! Models `ghidra.pcodeCPort.context.ContextSet`.

use crate::decompiler::seam_stubs::ConstructState;
use crate::decompiler::slghsymbol::TripleSymbol;

/// A single context register modification to apply during disassembly/parsing.
///
/// Records that bits `mask` of context word `num` should be set to `value`, resolved at address
/// `sym`, at the point in the parse tree given by `point`, and whether the new setting should
/// flow forward from its set point.
///
/// Models the data class `ghidra.pcodeCPort.context.ContextSet`, whose public fields (`sym`,
/// `point`, `num`, `mask`, `value`, `flow`) are exposed here as accessor methods so this can be
/// an object-safe trait.
pub trait ContextSet: Send + Sync {
    /// Resolves to the address where the setting takes effect (Java's `sym` field).
    fn sym(&self) -> &dyn TripleSymbol;

    /// The point in the parse tree at which the context set was made (Java's `point` field).
    fn point(&self) -> &dyn ConstructState;

    /// The number of the context word affected (Java's `num` field).
    fn num(&self) -> i32;

    /// The bits within the word affected (Java's `mask` field).
    fn mask(&self) -> i32;

    /// The new setting for the affected bits (Java's `value` field).
    fn value(&self) -> i32;

    /// Whether the new context flows forward from its set point (Java's `flow` field).
    fn flow(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::seam_stubs::PatternExpression;

    struct MockPattern;
    impl PatternExpression for MockPattern {}

    struct MockSymbol;
    impl TripleSymbol for MockSymbol {
        fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
            Box::new(MockPattern)
        }
    }

    struct MockConstructState;
    impl ConstructState for MockConstructState {}

    struct TestContextSet {
        sym: MockSymbol,
        point: MockConstructState,
        num: i32,
        mask: i32,
        value: i32,
        flow: bool,
    }

    impl ContextSet for TestContextSet {
        fn sym(&self) -> &dyn TripleSymbol {
            &self.sym
        }

        fn point(&self) -> &dyn ConstructState {
            &self.point
        }

        fn num(&self) -> i32 {
            self.num
        }

        fn mask(&self) -> i32 {
            self.mask
        }

        fn value(&self) -> i32 {
            self.value
        }

        fn flow(&self) -> bool {
            self.flow
        }
    }

    #[test]
    fn exposes_fields_via_accessors() {
        let set = TestContextSet {
            sym: MockSymbol,
            point: MockConstructState,
            num: 1,
            mask: 0x0000_ffff,
            value: 0x0000_00a5,
            flow: true,
        };

        assert_eq!(set.num(), 1);
        assert_eq!(set.mask(), 0x0000_ffff);
        assert_eq!(set.value(), 0x0000_00a5);
        assert!(set.flow());
        let _sym = set.sym();
        let _point = set.point();
    }

    #[test]
    fn works_as_trait_object() {
        let set: Box<dyn ContextSet> = Box::new(TestContextSet {
            sym: MockSymbol,
            point: MockConstructState,
            num: 2,
            mask: 0x0f0f_0f0f,
            value: 0,
            flow: false,
        });

        assert_eq!(set.num(), 2);
        assert!(!set.flow());
    }
}
