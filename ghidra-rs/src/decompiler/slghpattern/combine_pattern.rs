//! Models `ghidra.pcodeCPort.slghpattern.CombinePattern`.

use std::any::Any;
use std::io;

use crate::decompiler::slghpattern::context_pattern::ContextPattern;
use crate::decompiler::slghpattern::instruction_pattern::InstructionPattern;
use crate::decompiler::slghpattern::or_pattern::{clone_as_disjoint, OrPatternImpl};
use crate::decompiler::slghpattern::{DisjointPattern, Pattern, PatternBlock};
use crate::program::model::pcode::ids::ELEM_COMBINE_PAT;
use crate::program::model::pcode::Encoder;

/// A pattern that separately constrains both the context register and the instruction bytes.
///
/// Models `ghidra.pcodeCPort.slghpattern.CombinePattern`, a concrete [`DisjointPattern`] holding
/// one [`ContextPattern`] (its context-bit half) and one [`InstructionPattern`] (its
/// instruction-bit half) side by side -- unlike [`ContextPattern`]/[`InstructionPattern`]
/// themselves, which each only ever populate one half and leave the other `None`.
#[derive(Clone, Debug)]
pub struct CombinePattern {
    context: ContextPattern,
    instr: InstructionPattern,
}

impl CombinePattern {
    /// Creates a combine pattern from its context and instruction halves (Java's
    /// `CombinePattern(ContextPattern con, InstructionPattern in)`).
    pub fn new(context: ContextPattern, instr: InstructionPattern) -> Self {
        Self { context, instr }
    }
}

impl DisjointPattern for CombinePattern {
    fn get_block(&self, context: bool) -> Option<&PatternBlock> {
        if context {
            self.context.get_block()
        } else {
            self.instr.get_block()
        }
    }
}

impl Pattern for CombinePattern {
    fn simplify_clone(&self) -> Box<dyn Pattern> {
        if self.context.always_true() {
            return self.instr.simplify_clone();
        }
        if self.instr.always_true() {
            return self.context.simplify_clone();
        }
        if self.context.always_false() || self.instr.always_false() {
            return Box::new(InstructionPattern::with_truth(false));
        }
        Box::new(self.clone())
    }

    fn shift_instruction(&mut self, sa: i32) {
        self.instr.shift_instruction(sa);
    }

    fn always_true(&self) -> bool {
        self.context.always_true() && self.instr.always_true()
    }

    fn always_false(&self) -> bool {
        self.context.always_false() || self.instr.always_false()
    }

    fn always_instruction_true(&self) -> bool {
        self.instr.always_instruction_true()
    }

    fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if b.num_disjoint() > 0 {
            return b.do_and(self, -sa);
        }
        if let Some(b2) = (b as &dyn Any).downcast_ref::<CombinePattern>() {
            let c = downcast_context(self.context.do_and(&b2.context, 0));
            let i = downcast_instruction(self.instr.do_and(&b2.instr, sa));
            return Box::new(CombinePattern::new(c, i));
        }
        if let Some(b3) = (b as &dyn Any).downcast_ref::<InstructionPattern>() {
            let i = downcast_instruction(self.instr.do_and(b3, sa));
            let c = downcast_context(self.context.simplify_clone());
            return Box::new(CombinePattern::new(c, i));
        }
        // Must be a ContextPattern.
        let c = downcast_context(self.context.do_and(b, 0));
        let mut newpat = downcast_instruction(self.instr.simplify_clone());
        if sa < 0 {
            newpat.shift_instruction(-sa);
        }
        Box::new(CombinePattern::new(c, newpat))
    }

    fn common_sub_pattern(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if b.num_disjoint() > 0 {
            return b.common_sub_pattern(self, -sa);
        }
        if let Some(b2) = (b as &dyn Any).downcast_ref::<CombinePattern>() {
            let c = downcast_context(self.context.common_sub_pattern(&b2.context, 0));
            let i = downcast_instruction(self.instr.common_sub_pattern(&b2.instr, sa));
            return Box::new(CombinePattern::new(c, i));
        }
        if let Some(b3) = (b as &dyn Any).downcast_ref::<InstructionPattern>() {
            return self.instr.common_sub_pattern(b3, sa);
        }
        // Must be a ContextPattern.
        self.context.common_sub_pattern(b, 0)
    }

    fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if b.num_disjoint() > 0 {
            return b.do_or(self, -sa);
        }
        let mut res1 = clone_as_disjoint(self);
        let mut res2 = clone_as_disjoint(b);
        if sa < 0 {
            res1.shift_instruction(-sa);
        } else {
            res2.shift_instruction(sa);
        }
        Box::new(OrPatternImpl::with_pair(res1, res2))
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_COMBINE_PAT)?;
        self.context.encode(encoder)?;
        self.instr.encode(encoder)?;
        encoder.close_element(ELEM_COMBINE_PAT)?;
        Ok(())
    }
}

/// Downcasts a `Box<dyn Pattern>` known (by construction) to hold a `ContextPattern` -- every
/// caller here got it from `ContextPattern::do_and`/`simplify_clone`, whose own real bodies
/// always return `Box::new(ContextPattern { .. })`. Cloning the downcast (rather than trying to
/// move out of the trait object directly) sidesteps needing a `Pattern -> Any` box-coercion API;
/// mirrors Java's unchecked `(ContextPattern) context.doAnd(...)` cast.
fn downcast_context(p: Box<dyn Pattern>) -> ContextPattern {
    (p.as_ref() as &dyn Any)
        .downcast_ref::<ContextPattern>()
        .expect("expected ContextPattern::do_and/simplify_clone to return a ContextPattern")
        .clone()
}

/// Downcasts a `Box<dyn Pattern>` known (by construction) to hold an `InstructionPattern` -- see
/// [`downcast_context`] for why this is safe in practice.
fn downcast_instruction(p: Box<dyn Pattern>) -> InstructionPattern {
    (p.as_ref() as &dyn Any)
        .downcast_ref::<InstructionPattern>()
        .expect("expected InstructionPattern::do_and/simplify_clone to return an InstructionPattern")
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(mask: i32, val: i32) -> PatternBlock {
        PatternBlock::new(0, mask, val)
    }

    fn combine(ctx_mask: i32, ctx_val: i32, instr_mask: i32, instr_val: i32) -> CombinePattern {
        CombinePattern::new(
            ContextPattern::with_block(block(ctx_mask, ctx_val)),
            InstructionPattern::with_block(block(instr_mask, instr_val)),
        )
    }

    #[test]
    fn get_block_returns_context_or_instruction_half() {
        let p = combine(0xff, 0x11, 0x0f, 0x02);
        assert_eq!(DisjointPattern::get_block(&p, true), Some(&block(0xff, 0x11)));
        assert_eq!(DisjointPattern::get_block(&p, false), Some(&block(0x0f, 0x02)));
    }

    #[test]
    fn always_true_requires_both_halves_true() {
        let both_true = CombinePattern::new(
            ContextPattern::with_block(PatternBlock::always_true()),
            InstructionPattern::with_block(PatternBlock::always_true()),
        );
        assert!(both_true.always_true());

        let one_false = CombinePattern::new(
            ContextPattern::with_block(PatternBlock::always_true()),
            InstructionPattern::with_block(block(0xff, 0x11)),
        );
        assert!(!one_false.always_true());
    }

    #[test]
    fn always_false_when_either_half_false() {
        let p = CombinePattern::new(
            ContextPattern::with_block(PatternBlock::always_false()),
            InstructionPattern::with_block(block(0xff, 0x11)),
        );
        assert!(p.always_false());
    }

    #[test]
    fn always_instruction_true_delegates_to_instruction_half() {
        let p = CombinePattern::new(
            ContextPattern::with_block(block(0xff, 0x11)),
            InstructionPattern::with_block(PatternBlock::always_true()),
        );
        assert!(p.always_instruction_true());
    }

    #[test]
    fn shift_instruction_only_shifts_instruction_half() {
        let mut p = combine(0xff, 0x11, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let ctx_before = p.context.clone();
        p.shift_instruction(4);
        assert_eq!(p.context, ctx_before);
        let mut expected_instr = InstructionPattern::with_block(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        expected_instr.shift_instruction(4);
        assert_eq!(format!("{:?}", p.instr), format!("{:?}", expected_instr));
    }

    #[test]
    fn simplify_clone_returns_instruction_half_when_context_always_true() {
        let p = CombinePattern::new(
            ContextPattern::with_block(PatternBlock::always_true()),
            InstructionPattern::with_block(block(0xff, 0x11)),
        );
        let cloned = p.simplify_clone();
        assert!((cloned.as_ref() as &dyn Any).downcast_ref::<InstructionPattern>().is_some());
    }

    #[test]
    fn simplify_clone_returns_context_half_when_instruction_always_true() {
        let p = CombinePattern::new(
            ContextPattern::with_block(block(0xff, 0x11)),
            InstructionPattern::with_block(PatternBlock::always_true()),
        );
        let cloned = p.simplify_clone();
        assert!((cloned.as_ref() as &dyn Any).downcast_ref::<ContextPattern>().is_some());
    }

    #[test]
    fn simplify_clone_returns_always_false_instruction_pattern_when_either_half_false() {
        let p = CombinePattern::new(
            ContextPattern::with_block(PatternBlock::always_false()),
            InstructionPattern::with_block(block(0xff, 0x11)),
        );
        let cloned = p.simplify_clone();
        assert!(cloned.always_false());
    }

    #[test]
    fn simplify_clone_returns_combine_pattern_when_neither_half_resolves() {
        let p = combine(0xff, 0x11, 0x0f, 0x02);
        let cloned = p.simplify_clone();
        assert!((cloned.as_ref() as &dyn Any).downcast_ref::<CombinePattern>().is_some());
    }

    #[test]
    fn do_and_with_another_combine_pattern_intersects_both_halves() {
        let a = combine(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32, 0xff, 0x11);
        let b = combine(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32, 0x0f, 0x01);
        let result = a.do_and(&b, 0);
        assert!((result.as_ref() as &dyn Any).downcast_ref::<CombinePattern>().is_some());
    }

    #[test]
    fn do_and_with_instruction_pattern_combines_instruction_half_only() {
        let a = combine(0xff, 0x11, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = InstructionPattern::with_block(block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32));
        let result = a.do_and(&b, 0);
        let result = (result.as_ref() as &dyn Any).downcast_ref::<CombinePattern>().unwrap();
        assert_eq!(result.context, a.context);
    }

    #[test]
    fn do_and_with_context_pattern_combines_context_half_only() {
        let a = combine(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32, 0xff, 0x11);
        let b = ContextPattern::with_block(block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32));
        let result = a.do_and(&b, 0);
        let result = (result.as_ref() as &dyn Any).downcast_ref::<CombinePattern>().unwrap();
        assert_eq!(
            result.context.get_block(),
            Some(&a.context.get_block().unwrap().intersect(b.get_block().unwrap()))
        );
    }

    #[test]
    fn do_or_returns_or_pattern_with_both_disjuncts() {
        let a = combine(0xff, 0x11, 0x0f, 0x02);
        let b = combine(0x0f, 0x01, 0xff, 0x22);
        let result = a.do_or(&b, 0);
        assert_eq!(result.num_disjoint(), 2);
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
    fn encode_wraps_both_halves() {
        let p = combine(0xff, 0x11, 0x0f, 0x02);
        let mut encoder = RecordingEncoder::default();
        p.encode(&mut encoder).unwrap();
        assert_eq!(
            encoder.opened,
            vec!["combine_pat", "context_pat", "pat_block", "mask_word", "instruct_pat", "pat_block", "mask_word"]
        );
        assert_eq!(
            encoder.closed,
            vec!["mask_word", "pat_block", "context_pat", "mask_word", "pat_block", "instruct_pat", "combine_pat"]
        );
    }
}
