//! Models `ghidra.pcodeCPort.slghpattern.OrPattern`.

use crate::decompiler::slghpattern::pattern::Pattern;
use crate::decompiler::slghpattern::DisjointPattern;

/// A pattern that matches if any of its disjuncts match.
///
/// Models `ghidra.pcodeCPort.slghpattern.OrPattern`, a concrete subclass of [`Pattern`] holding
/// an ordered list of [`DisjointPattern`]s. Extracted as a trait, keyed off an
/// [`or_list`](OrPattern::or_list) accessor, to break the dependency cycle between `OrPattern`,
/// `DisjointPattern`, and the concrete disjunct types (`InstructionPattern`, `ContextPattern`,
/// `CombinePattern`) that are not yet ported.
///
/// Only `or_list()` lives here. Every `Pattern`-abstract method (`numDisjoint`/`getDisjoint`
/// included -- Java's `OrPattern` overrides both to reflect `orlist`, differently from
/// `DisjointPattern`'s 0/null override) belongs on each concrete implementor's own `impl
/// Pattern for X` block instead: Rust has no mechanism for a subtrait to override a supertrait
/// method the way Java overriding works, so redeclaring them here would just create a second,
/// ambiguous same-named method rather than replacing `Pattern`'s default. `Pattern::num_disjoint`
/// docs this exact tradeoff.
pub trait OrPattern: Pattern {
    /// The disjuncts being OR-ed together (`orlist` in Java).
    fn or_list(&self) -> &[Box<dyn DisjointPattern>];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghpattern::PatternBlock;

    /// Trivial mock disjunct, proving [`DisjointPattern`] usage from within an `OrPattern` impl.
    struct MockDisjoint {
        instr: Option<PatternBlock>,
    }

    impl Pattern for MockDisjoint {
        fn simplify_clone(&self) -> Box<dyn Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn shift_instruction(&mut self, _sa: i32) {}
        fn do_or(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn do_and(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn common_sub_pattern(&self, _b: &dyn Pattern, _sa: i32) -> Box<dyn Pattern> {
            unimplemented!("not exercised by these tests")
        }
        fn always_true(&self) -> bool {
            false
        }
        fn always_false(&self) -> bool {
            false
        }
        fn always_instruction_true(&self) -> bool {
            false
        }
        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl DisjointPattern for MockDisjoint {
        fn get_block(&self, context: bool) -> Option<&PatternBlock> {
            if context {
                None
            } else {
                self.instr.as_ref()
            }
        }
    }

    /// Trivial mock `OrPattern`. `num_disjoint`/`get_disjoint` are implemented on the `Pattern`
    /// impl block (not `OrPattern` -- see the trait doc for why), delegating to `or_list()`,
    /// proving that delegation behaves like the Java `OrPattern` override.
    struct MockOr {
        orlist: Vec<Box<dyn DisjointPattern>>,
    }

    impl OrPattern for MockOr {
        fn or_list(&self) -> &[Box<dyn DisjointPattern>] {
            &self.orlist
        }
    }

    impl Pattern for MockOr {
        fn num_disjoint(&self) -> i32 {
            self.or_list().len() as i32
        }

        fn get_disjoint(&self, i: i32) -> Option<&dyn DisjointPattern> {
            if i < 0 {
                return None;
            }
            self.or_list().get(i as usize).map(|b| b.as_ref())
        }

        fn simplify_clone(&self) -> Box<dyn Pattern> {
            Box::new(MockOr { orlist: Vec::new() })
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

        fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::Encoder) -> std::io::Result<()> {
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

        assert_eq!(Pattern::num_disjoint(&or_pattern), 2);
        assert!(Pattern::get_disjoint(&or_pattern, 0).is_some());
        assert!(Pattern::get_disjoint(&or_pattern, 1).is_some());
        assert!(Pattern::get_disjoint(&or_pattern, 2).is_none());
        assert!(Pattern::get_disjoint(&or_pattern, -1).is_none());
    }

    #[test]
    fn empty_or_list_has_no_disjuncts() {
        let or_pattern = MockOr { orlist: Vec::new() };
        assert_eq!(Pattern::num_disjoint(&or_pattern), 0);
        assert!(Pattern::get_disjoint(&or_pattern, 0).is_none());
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
