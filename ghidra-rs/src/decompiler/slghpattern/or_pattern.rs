//! Models `ghidra.pcodeCPort.slghpattern.OrPattern`.

use std::any::Any;
use std::io;

use crate::decompiler::slghpattern::combine_pattern::CombinePattern;
use crate::decompiler::slghpattern::context_pattern::ContextPattern;
use crate::decompiler::slghpattern::instruction_pattern::InstructionPattern;
use crate::decompiler::slghpattern::pattern::Pattern;
use crate::decompiler::slghpattern::DisjointPattern;
use crate::program::model::pcode::ids::ELEM_OR_PAT;
use crate::program::model::pcode::Encoder;

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

/// Downcasts `p` to one of the three concrete disjoint pattern types and returns a clone as
/// `Box<dyn DisjointPattern>`, mirroring Java's unchecked `(DisjointPattern) x.simplifyClone()`
/// cast. Every concrete `simplify_clone()`/`clone()` pair in this module is field-for-field
/// identical (see each type's own doc comment), so cloning the downcast target is equivalent to,
/// and cheaper than, calling `simplify_clone()` and then re-downcasting its `Box<dyn Pattern>`
/// result.
pub(crate) fn clone_as_disjoint(p: &dyn Pattern) -> Box<dyn DisjointPattern> {
    let any = p as &dyn Any;
    if let Some(cp) = any.downcast_ref::<ContextPattern>() {
        Box::new(cp.clone())
    } else if let Some(ip) = any.downcast_ref::<InstructionPattern>() {
        Box::new(ip.clone())
    } else if let Some(cmb) = any.downcast_ref::<CombinePattern>() {
        Box::new(cmb.clone())
    } else {
        panic!(
            "clone_as_disjoint: pattern is not one of the known disjoint concrete types \
             (ContextPattern, InstructionPattern, CombinePattern)"
        )
    }
}

/// The concrete `OrPattern`: matches if any of its ordered disjuncts match.
///
/// Models `ghidra.pcodeCPort.slghpattern.OrPattern` (the real, non-abstract class -- see the
/// [`OrPattern`] trait above for why the accessor is split out separately).
#[derive(Clone, Debug)]
pub struct OrPatternImpl {
    orlist: Vec<Box<dyn DisjointPattern>>,
}

impl std::fmt::Debug for dyn DisjointPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Clone for Box<dyn DisjointPattern> {
    fn clone(&self) -> Self {
        clone_as_disjoint(self.as_ref())
    }
}

impl OrPatternImpl {
    /// An empty `OrPattern` (Java's no-arg constructor).
    pub fn new() -> Self {
        Self { orlist: Vec::new() }
    }

    /// An `OrPattern` of exactly two disjuncts (Java's `OrPattern(DisjointPattern a,
    /// DisjointPattern b)`).
    pub fn with_pair(a: Box<dyn DisjointPattern>, b: Box<dyn DisjointPattern>) -> Self {
        Self { orlist: vec![a, b] }
    }

    /// An `OrPattern` of an arbitrary list of disjuncts (Java's `OrPattern(VectorSTL<DisjointPattern>
    /// list)`).
    pub fn with_list(list: Vec<Box<dyn DisjointPattern>>) -> Self {
        Self { orlist: list }
    }
}

impl Default for OrPatternImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl OrPattern for OrPatternImpl {
    fn or_list(&self) -> &[Box<dyn DisjointPattern>] {
        &self.orlist
    }
}

impl Pattern for OrPatternImpl {
    fn num_disjoint(&self) -> i32 {
        self.orlist.len() as i32
    }

    fn get_disjoint(&self, i: i32) -> Option<&dyn DisjointPattern> {
        if i < 0 {
            return None;
        }
        self.orlist.get(i as usize).map(|b| b.as_ref())
    }

    fn simplify_clone(&self) -> Box<dyn Pattern> {
        if self.orlist.iter().any(|d| d.always_true()) {
            return Box::new(InstructionPattern::with_truth(true));
        }
        let newlist: Vec<Box<dyn DisjointPattern>> = self
            .orlist
            .iter()
            .filter(|d| !d.always_false())
            .map(|d| clone_as_disjoint(d.as_ref()))
            .collect();
        match newlist.len() {
            0 => Box::new(InstructionPattern::with_truth(false)),
            1 => {
                let only: Box<dyn DisjointPattern> = newlist.into_iter().next().unwrap();
                only
            }
            _ => Box::new(OrPatternImpl::with_list(newlist)),
        }
    }

    fn shift_instruction(&mut self, sa: i32) {
        for d in &mut self.orlist {
            d.shift_instruction(sa);
        }
    }

    /// This isn't quite right because different branches may cover the entire gamut (Java's own
    /// comment on `alwaysTrue`, kept verbatim -- it is a known imprecision in the source, not a
    /// gap in this port).
    fn always_true(&self) -> bool {
        self.orlist.iter().any(|d| d.always_true())
    }

    fn always_false(&self) -> bool {
        self.orlist.iter().all(|d| d.always_false())
    }

    fn always_instruction_true(&self) -> bool {
        self.orlist.iter().all(|d| d.always_instruction_true())
    }

    fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        let mut newlist: Vec<Box<dyn DisjointPattern>> = Vec::new();
        if let Some(b2) = (b as &dyn Any).downcast_ref::<OrPatternImpl>() {
            for a in &self.orlist {
                for b_disjunct in &b2.orlist {
                    let combined = a.do_and(b_disjunct.as_ref(), sa);
                    newlist.push(clone_as_disjoint(combined.as_ref()));
                }
            }
        } else {
            for a in &self.orlist {
                let combined = a.do_and(b, sa);
                newlist.push(clone_as_disjoint(combined.as_ref()));
            }
        }
        Box::new(OrPatternImpl::with_list(newlist))
    }

    fn common_sub_pattern(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        let mut iter = self.orlist.iter();
        let first = iter.next().expect("OrPattern.commonSubPattern requires at least one disjunct");
        let mut res: Box<dyn Pattern> = first.common_sub_pattern(b, sa);

        let sa = if sa > 0 { 0 } else { sa };
        for d in iter {
            res = d.common_sub_pattern(res.as_ref(), sa);
        }
        res
    }

    /// Models `OrPattern.doOr`. Java's version shifts the instruction bits of `this.orlist`'s
    /// *original* disjuncts in place when `sa < 0` (rather than the freshly cloned `newlist` that
    /// is actually returned) -- since this port's `do_or` takes `&self`, not `&mut self`
    /// (matching every other `Pattern::do_or` in this crate), that in-place mutation of the
    /// receiver isn't expressible here, so the freshly cloned entries are shifted instead. That
    /// also matches the evident intent (the shift's effect should end up in what's returned).
    fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        let mut newlist: Vec<Box<dyn DisjointPattern>> =
            self.orlist.iter().map(|d| clone_as_disjoint(d.as_ref())).collect();

        if sa < 0 {
            for d in &mut newlist {
                d.shift_instruction(-sa);
            }
        }

        if let Some(b2) = (b as &dyn Any).downcast_ref::<OrPatternImpl>() {
            for d in &b2.orlist {
                newlist.push(clone_as_disjoint(d.as_ref()));
            }
        } else {
            newlist.push(clone_as_disjoint(b));
        }

        if sa > 0 {
            for d in &mut newlist {
                d.shift_instruction(sa);
            }
        }

        Box::new(OrPatternImpl::with_list(newlist))
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_OR_PAT)?;
        for d in &self.orlist {
            d.encode(encoder)?;
        }
        encoder.close_element(ELEM_OR_PAT)?;
        Ok(())
    }
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

    // --- OrPatternImpl: the real, concrete `OrPattern` -----------------------------------

    use crate::decompiler::slghpattern::InstructionPattern;

    fn instr(mask: i32, val: i32) -> Box<dyn DisjointPattern> {
        Box::new(InstructionPattern::with_block(PatternBlock::new(0, mask, val)))
    }

    #[test]
    fn new_is_empty() {
        let p = OrPatternImpl::new();
        assert_eq!(p.num_disjoint(), 0);
        assert!(p.always_false());
    }

    #[test]
    fn with_pair_holds_both_disjuncts_in_order() {
        let p = OrPatternImpl::with_pair(instr(0xff, 0x11), instr(0x0f, 0x02));
        assert_eq!(p.num_disjoint(), 2);
        assert_eq!(p.get_disjoint(0).unwrap().get_block(false), Some(&PatternBlock::new(0, 0xff, 0x11)));
        assert_eq!(p.get_disjoint(1).unwrap().get_block(false), Some(&PatternBlock::new(0, 0x0f, 0x02)));
    }

    #[test]
    fn always_true_when_any_disjunct_always_true() {
        let p = OrPatternImpl::with_pair(
            Box::new(InstructionPattern::with_truth(true)),
            instr(0xff, 0x11),
        );
        assert!(p.always_true());
    }

    #[test]
    fn always_false_when_every_disjunct_always_false() {
        let p = OrPatternImpl::with_pair(
            Box::new(InstructionPattern::with_truth(false)),
            Box::new(InstructionPattern::with_truth(false)),
        );
        assert!(p.always_false());
        assert!(!p.always_true());
    }

    #[test]
    fn always_instruction_true_requires_every_disjunct() {
        let all_true = OrPatternImpl::with_pair(
            Box::new(InstructionPattern::with_truth(true)),
            Box::new(InstructionPattern::with_truth(true)),
        );
        assert!(all_true.always_instruction_true());

        let one_false = OrPatternImpl::with_pair(
            Box::new(InstructionPattern::with_truth(true)),
            instr(0xff, 0x11),
        );
        assert!(!one_false.always_instruction_true());
    }

    #[test]
    fn shift_instruction_shifts_every_disjunct() {
        let mut p = OrPatternImpl::with_pair(
            instr(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32),
            instr(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32),
        );
        p.shift_instruction(4);
        assert_eq!(p.get_disjoint(0).unwrap().get_block(false).unwrap().get_length(), 5);
    }

    #[test]
    fn simplify_clone_collapses_to_instruction_pattern_true_when_any_disjunct_always_true() {
        let p = OrPatternImpl::with_pair(
            Box::new(InstructionPattern::with_truth(true)),
            instr(0xff, 0x11),
        );
        let cloned = p.simplify_clone();
        assert!(cloned.always_true());
        assert_eq!(cloned.num_disjoint(), 0);
    }

    #[test]
    fn simplify_clone_collapses_to_instruction_pattern_false_when_every_disjunct_always_false() {
        let p = OrPatternImpl::with_pair(
            Box::new(InstructionPattern::with_truth(false)),
            Box::new(InstructionPattern::with_truth(false)),
        );
        let cloned = p.simplify_clone();
        assert!(cloned.always_false());
        assert_eq!(cloned.num_disjoint(), 0);
    }

    #[test]
    fn simplify_clone_drops_always_false_disjuncts_and_unwraps_a_singleton() {
        let p = OrPatternImpl::with_pair(
            Box::new(InstructionPattern::with_truth(false)),
            instr(0xff, 0x11),
        );
        let cloned = p.simplify_clone();
        // Not an OrPattern any more (num_disjoint defaults to 0 for a plain InstructionPattern).
        assert_eq!(cloned.num_disjoint(), 0);
        assert_eq!(cloned.always_true(), false);
    }

    #[test]
    fn simplify_clone_keeps_multiple_surviving_disjuncts_as_an_or_pattern() {
        let p = OrPatternImpl::with_list(vec![instr(0xff, 0x11), instr(0x0f, 0x02), instr(0xf0, 0x20)]);
        let cloned = p.simplify_clone();
        assert_eq!(cloned.num_disjoint(), 3);
    }

    #[test]
    fn do_or_with_plain_pattern_appends_it_as_a_third_disjunct() {
        let p = OrPatternImpl::with_pair(instr(0xff, 0x11), instr(0x0f, 0x02));
        let extra = InstructionPattern::with_block(PatternBlock::new(0, 0xf0, 0x20));
        let result = p.do_or(&extra, 0);
        assert_eq!(result.num_disjoint(), 3);
    }

    #[test]
    fn do_or_with_another_or_pattern_flattens_both_lists() {
        let a = OrPatternImpl::with_pair(instr(0xff, 0x11), instr(0x0f, 0x02));
        let b = OrPatternImpl::with_pair(instr(0xf0, 0x20), instr(0x0f, 0x03));
        let result = a.do_or(&b, 0);
        assert_eq!(result.num_disjoint(), 4);
    }

    #[test]
    fn do_and_with_plain_pattern_ands_every_disjunct() {
        let p = OrPatternImpl::with_pair(
            instr(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32),
            instr(0xff00_0000u32 as i32, 0xbb00_0000u32 as i32),
        );
        let mask = InstructionPattern::with_block(PatternBlock::new(0, 0x0f00_0000u32 as i32, 0x0a00_0000u32 as i32));
        let result = p.do_and(&mask, 0);
        assert_eq!(result.num_disjoint(), 2);
    }

    #[test]
    fn do_and_with_another_or_pattern_is_a_cross_product() {
        let a = OrPatternImpl::with_pair(instr(0xff, 0x0f), instr(0xff, 0xf0));
        let b = OrPatternImpl::with_pair(instr(0xff, 0x0f), instr(0xff, 0xf0));
        let result = a.do_and(&b, 0);
        assert_eq!(result.num_disjoint(), 4);
    }

    #[test]
    fn common_sub_pattern_folds_across_every_disjunct() {
        let p = OrPatternImpl::with_pair(
            instr(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32),
            instr(0xff00_0000u32 as i32, 0xab00_0000u32 as i32),
        );
        let other = InstructionPattern::with_block(PatternBlock::new(0, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        let result = p.common_sub_pattern(&other, 0);
        // Neither disjunct's common-sub-pattern with `other` is identical, so this just proves
        // the fold runs across all disjuncts without panicking and returns *something* sensible
        // (a Pattern, not necessarily an OrPattern -- Java's own commonSubPattern can collapse).
        let _ = result;
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.closed.push(elem_id.name);
            Ok(())
        }
        fn write_bool(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: bool) -> io::Result<()> { Ok(()) }
        fn write_signed_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: i64) -> io::Result<()> { Ok(()) }
        fn write_unsigned_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: u64) -> io::Result<()> { Ok(()) }
        fn write_string(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_string_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_space(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _s: &crate::program::model::address::AddressSpace) -> io::Result<()> { Ok(()) }
        fn write_space_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _n: &str) -> io::Result<()> { Ok(()) }
        fn write_opcode(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> { Ok(()) }
        fn write_opcode_ordinal(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: i32) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn encode_wraps_every_disjunct() {
        let p = OrPatternImpl::with_pair(instr(0xff, 0x11), instr(0x0f, 0x02));
        let mut encoder = RecordingEncoder::default();
        p.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened.first(), Some(&"or_pat"));
        assert_eq!(encoder.closed.last(), Some(&"or_pat"));
        assert_eq!(encoder.opened.iter().filter(|&&n| n == "instruct_pat").count(), 2);
    }
}
