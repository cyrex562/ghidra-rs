//! Models `ghidra.pcodeCPort.slghpattern.InstructionPattern`.

use std::any::Any;
use std::fmt;
use std::io;

use crate::decompiler::slghpattern::combine_pattern::CombinePattern;
use crate::decompiler::slghpattern::context_pattern::ContextPattern;
use crate::decompiler::slghpattern::or_pattern::{clone_as_disjoint, OrPatternImpl};
use crate::decompiler::slghpattern::{DisjointPattern, Pattern, PatternBlock};
use crate::program::model::pcode::ids::ELEM_INSTRUCT_PAT;
use crate::program::model::pcode::Encoder;

/// A pattern that only constrains the instruction bytes, placing no constraint on the
/// disassembly context register.
///
/// Models `ghidra.pcodeCPort.slghpattern.InstructionPattern`, a concrete [`DisjointPattern`]
/// whose context-bit half ([`DisjointPattern::get_block`] with `context = true`) is always
/// `None`.
#[derive(Clone, Debug, PartialEq)]
pub struct InstructionPattern {
    maskvalue: Option<PatternBlock>,
}

impl InstructionPattern {
    /// An unconstrained instruction pattern (Java's no-arg constructor).
    pub fn new() -> Self {
        Self { maskvalue: None }
    }

    /// An instruction pattern constrained by `mv` (Java's `InstructionPattern(PatternBlock mv)`).
    pub fn with_block(mv: PatternBlock) -> Self {
        Self { maskvalue: Some(mv) }
    }

    /// An always-true (`tf = true`) or always-false (`tf = false`) instruction pattern (Java's
    /// `InstructionPattern(boolean tf)`, which builds `new PatternBlock(tf)`).
    pub fn with_truth(tf: bool) -> Self {
        let block = if tf { PatternBlock::always_true() } else { PatternBlock::always_false() };
        Self { maskvalue: Some(block) }
    }

    /// The instruction block this pattern constrains (Java's `getBlock()` no-arg overload).
    pub fn get_block(&self) -> Option<&PatternBlock> {
        self.maskvalue.as_ref()
    }
}

impl Default for InstructionPattern {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for InstructionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.maskvalue {
            Some(block) => write!(f, "InstructionPattern{{{}}}", block),
            None => write!(f, "InstructionPattern{{null}}"),
        }
    }
}

impl DisjointPattern for InstructionPattern {
    fn get_block(&self, context: bool) -> Option<&PatternBlock> {
        if context {
            None
        } else {
            self.maskvalue.as_ref()
        }
    }
}

impl Pattern for InstructionPattern {
    fn simplify_clone(&self) -> Box<dyn Pattern> {
        Box::new(self.clone())
    }

    fn shift_instruction(&mut self, sa: i32) {
        if let Some(block) = &mut self.maskvalue {
            block.shift(sa);
        }
    }

    fn always_true(&self) -> bool {
        self.maskvalue.as_ref().map(PatternBlock::is_always_true).unwrap_or(true)
    }

    fn always_false(&self) -> bool {
        self.maskvalue.as_ref().map(PatternBlock::is_always_false).unwrap_or(false)
    }

    fn always_instruction_true(&self) -> bool {
        self.always_true()
    }

    fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if b.num_disjoint() > 0 {
            return b.do_and(self, -sa);
        }
        if (b as &dyn Any).downcast_ref::<CombinePattern>().is_some() {
            return b.do_and(self, -sa);
        }
        if let Some(b3) = (b as &dyn Any).downcast_ref::<ContextPattern>() {
            let mut newpat = self.clone();
            if sa < 0 {
                newpat.shift_instruction(-sa);
            }
            return Box::new(CombinePattern::new(b3.clone(), newpat));
        }
        let b4 = (b as &dyn Any)
            .downcast_ref::<InstructionPattern>()
            .expect("InstructionPattern::do_and: b is neither CombinePattern, ContextPattern, nor InstructionPattern");

        let mine = self.maskvalue.as_ref().expect("InstructionPattern::do_and requires a constrained block");
        let other = b4.maskvalue.as_ref().expect("InstructionPattern::do_and requires a constrained block");
        let respattern = if sa < 0 {
            let mut a = mine.clone();
            a.shift(-sa);
            a.intersect(other)
        } else {
            let mut c = other.clone();
            c.shift(sa);
            mine.intersect(&c)
        };
        Box::new(InstructionPattern::with_block(respattern))
    }

    fn common_sub_pattern(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if b.num_disjoint() > 0 {
            return b.common_sub_pattern(self, -sa);
        }
        if (b as &dyn Any).downcast_ref::<CombinePattern>().is_some() {
            return b.common_sub_pattern(self, -sa);
        }
        if (b as &dyn Any).downcast_ref::<ContextPattern>().is_some() {
            return Box::new(InstructionPattern::with_truth(true));
        }
        let b4 = (b as &dyn Any)
            .downcast_ref::<InstructionPattern>()
            .expect("InstructionPattern::common_sub_pattern: b is neither CombinePattern, ContextPattern, nor InstructionPattern");

        let mine = self.maskvalue.as_ref().expect("InstructionPattern::common_sub_pattern requires a constrained block");
        let other = b4.maskvalue.as_ref().expect("InstructionPattern::common_sub_pattern requires a constrained block");
        let respattern = if sa < 0 {
            let mut a = mine.clone();
            a.shift(-sa);
            a.common_sub_pattern(other)
        } else {
            let mut c = other.clone();
            c.shift(sa);
            mine.common_sub_pattern(&c)
        };
        Box::new(InstructionPattern::with_block(respattern))
    }

    fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if b.num_disjoint() > 0 {
            return b.do_or(self, -sa);
        }
        if (b as &dyn Any).downcast_ref::<CombinePattern>().is_some() {
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
        encoder.open_element(ELEM_INSTRUCT_PAT)?;
        if let Some(maskvalue) = &self.maskvalue {
            maskvalue.encode(encoder)?;
        }
        encoder.close_element(ELEM_INSTRUCT_PAT)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(mask: i32, val: i32) -> PatternBlock {
        PatternBlock::new(0, mask, val)
    }

    #[test]
    fn new_is_unconstrained() {
        let p = InstructionPattern::new();
        assert!(p.get_block().is_none());
        assert!(DisjointPattern::get_block(&p, true).is_none());
    }

    #[test]
    fn with_block_stores_instruction_block_only() {
        let b = block(0xff, 0xaa);
        let p = InstructionPattern::with_block(b.clone());
        assert_eq!(DisjointPattern::get_block(&p, false), Some(&b));
        assert!(DisjointPattern::get_block(&p, true).is_none());
    }

    #[test]
    fn with_truth_matches_always_true_and_false() {
        assert!(InstructionPattern::with_truth(true).always_true());
        assert!(InstructionPattern::with_truth(false).always_false());
    }

    #[test]
    fn shift_instruction_shifts_the_block() {
        let mut p = InstructionPattern::with_block(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        let mut expected = block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        expected.shift(4);
        p.shift_instruction(4);
        assert_eq!(p.maskvalue, Some(expected));
    }

    #[test]
    fn do_and_with_instruction_pattern_intersects_blocks() {
        let a = InstructionPattern::with_block(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        let b = InstructionPattern::with_block(block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32));
        let result = a.do_and(&b, 0);
        let result = (result.as_ref() as &dyn Any)
            .downcast_ref::<InstructionPattern>()
            .expect("do_and of two InstructionPatterns returns an InstructionPattern");
        assert_eq!(
            result.maskvalue,
            Some(a.maskvalue.as_ref().unwrap().intersect(b.maskvalue.as_ref().unwrap()))
        );
    }

    #[test]
    fn do_and_with_context_pattern_returns_combine_pattern() {
        let instr = InstructionPattern::with_block(block(0xff, 0xaa));
        let ctx = ContextPattern::with_block(block(0x0f, 0x05));
        let result = instr.do_and(&ctx, 0);
        assert!((result.as_ref() as &dyn Any).downcast_ref::<CombinePattern>().is_some());
    }

    #[test]
    fn common_sub_pattern_with_context_pattern_is_always_true() {
        let instr = InstructionPattern::with_block(block(0xff, 0xaa));
        let ctx = ContextPattern::with_block(block(0x0f, 0x05));
        let result = instr.common_sub_pattern(&ctx, 0);
        assert!(result.always_true());
    }

    #[test]
    fn do_or_with_instruction_pattern_returns_or_pattern_with_both_disjuncts() {
        let a = InstructionPattern::with_block(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        let b = InstructionPattern::with_block(block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32));
        let result = a.do_or(&b, 0);
        assert_eq!(result.num_disjoint(), 2);
    }

    #[test]
    fn display_shows_block_or_null() {
        assert_eq!(InstructionPattern::new().to_string(), "InstructionPattern{null}");
        let p = InstructionPattern::with_block(block(0xf000_0000u32 as i32, 0x9000_0000u32 as i32));
        assert!(p.to_string().starts_with("InstructionPattern{"));
        assert!(p.to_string().contains("1001...."));
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
    fn encode_writes_element_and_block() {
        let p = InstructionPattern::with_block(block(0xff, 0xaa));
        let mut encoder = RecordingEncoder::default();
        p.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["instruct_pat", "pat_block", "mask_word"]);
        assert_eq!(encoder.closed, vec!["mask_word", "pat_block", "instruct_pat"]);
    }
}
