//! Models `ghidra.pcodeCPort.slghpattern.OrPattern`.

use std::io;

use crate::decompiler::seam_stubs::Pattern;
use crate::decompiler::slghpattern::DisjointPattern;
use crate::program::model::pcode::Encoder;

/// A pattern that matches if any of its disjuncts match.
///
/// Models `ghidra.pcodeCPort.slghpattern.OrPattern`, a concrete subclass of `Pattern` (stubbed as
/// [`Pattern`] pending its own port) holding an ordered list of [`DisjointPattern`]s. Extracted as
/// a trait, keyed off an [`or_list`](OrPattern::or_list) accessor, to break the dependency cycle
/// between `OrPattern`, `DisjointPattern`, and the concrete disjunct types (`InstructionPattern`,
/// `ContextPattern`, `CombinePattern`) that are not yet ported.
pub trait OrPattern: Pattern {
    /// The disjuncts being OR-ed together (`orlist` in Java).
    fn or_list(&self) -> &[Box<dyn DisjointPattern>];

    /// The number of disjuncts.
    fn num_disjoint(&self) -> i32 {
        self.or_list().len() as i32
    }

    /// The `i`th disjunct, or `None` if out of range.
    fn get_disjoint(&self, i: i32) -> Option<&dyn DisjointPattern> {
        if i < 0 {
            return None;
        }
        self.or_list().get(i as usize).map(|b| b.as_ref())
    }

    /// Shifts every disjunct's instruction pattern by `sa`.
    fn shift_instruction(&mut self, sa: i32);

    /// Whether any disjunct always matches.
    ///
    /// Note (per the original Java comment): this isn't quite right, since different branches
    /// may together cover the entire gamut without any single one being always-true.
    fn always_true(&self) -> bool;

    /// Whether every disjunct never matches.
    fn always_false(&self) -> bool;

    /// Whether every disjunct's instruction portion always matches.
    fn always_instruction_true(&self) -> bool;

    /// ANDs this pattern with `b`, distributing over disjuncts.
    fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// The common sub-pattern shared by all of this pattern's disjuncts and `b`.
    fn common_sub_pattern(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// ORs this pattern with `b`, concatenating disjunct lists.
    fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// Simplifies this pattern, eliminating always-false disjuncts and collapsing to a single
    /// disjunct (or an always-true/always-false instruction pattern) where possible.
    fn simplify_clone(&self) -> Box<dyn Pattern>;

    /// Encodes this pattern to the given encoder.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpattern::PatternBlock;

    /// Trivial mock disjunct, proving [`DisjointPattern`] usage from within an `OrPattern` impl.
    struct MockDisjoint {
        instr: Option<PatternBlock>,
    }

    impl Pattern for MockDisjoint {}

    impl DisjointPattern for MockDisjoint {
        fn get_block(&self, context: bool) -> Option<&PatternBlock> {
            if context {
                None
            } else {
                self.instr.as_ref()
            }
        }
    }

    /// Trivial mock `OrPattern`, proving the trait is object-safe and that the default
    /// `or_list`-derived methods behave like the Java overrides.
    struct MockOr {
        orlist: Vec<Box<dyn DisjointPattern>>,
    }

    impl Pattern for MockOr {}

    impl OrPattern for MockOr {
        fn or_list(&self) -> &[Box<dyn DisjointPattern>] {
            &self.orlist
        }

        fn shift_instruction(&mut self, _sa: i32) {}

        fn always_true(&self) -> bool {
            false
        }

        fn always_false(&self) -> bool {
            self.orlist.is_empty()
        }

        fn always_instruction_true(&self) -> bool {
            false
        }

        fn do_and(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            Box::new(MockOr { orlist: Vec::new() })
        }

        fn common_sub_pattern(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            Box::new(MockOr { orlist: Vec::new() })
        }

        fn do_or(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            Box::new(MockOr { orlist: Vec::new() })
        }

        fn simplify_clone(&self) -> Box<dyn Pattern> {
            Box::new(MockOr { orlist: Vec::new() })
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn num_disjoint_and_get_disjoint_reflect_or_list() {
        let a: Box<dyn DisjointPattern> = Box::new(MockDisjoint { instr: None });
        let b: Box<dyn DisjointPattern> = Box::new(MockDisjoint {
            instr: Some(PatternBlock::new(0, 0xff, 0xab)),
        });
        let or_pattern = MockOr { orlist: vec![a, b] };

        assert_eq!(or_pattern.num_disjoint(), 2);
        assert!(or_pattern.get_disjoint(0).is_some());
        assert!(or_pattern.get_disjoint(1).is_some());
        assert!(or_pattern.get_disjoint(2).is_none());
        assert!(or_pattern.get_disjoint(-1).is_none());
    }

    #[test]
    fn empty_or_list_has_no_disjuncts() {
        let or_pattern = MockOr { orlist: Vec::new() };
        assert_eq!(or_pattern.num_disjoint(), 0);
        assert!(or_pattern.get_disjoint(0).is_none());
        assert!(or_pattern.always_false());
    }

    #[test]
    fn trait_object_is_usable_through_dyn_pattern() {
        let or_pattern = MockOr { orlist: Vec::new() };
        let dyn_pattern: &dyn Pattern = &or_pattern;
        // Object-safety smoke check: constructing the trait object above must compile.
        let _ = dyn_pattern;
    }
}
