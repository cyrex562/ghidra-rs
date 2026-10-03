//! Models `ghidra.pcodeCPort.slghpattern.ContextPattern`.

use std::any::Any;
use std::io;

use crate::decompiler::slghpattern::or_pattern::OrPatternImpl;
use crate::decompiler::slghpattern::{DisjointPattern, Pattern, PatternBlock};
use crate::program::model::pcode::ids::ELEM_CONTEXT_PAT;
use crate::program::model::pcode::Encoder;

/// A pattern that only constrains the disassembly context register, placing no constraint on
/// the instruction bytes themselves.
///
/// Models `ghidra.pcodeCPort.slghpattern.ContextPattern`, a concrete [`DisjointPattern`] whose
/// instruction-bit half ([`DisjointPattern::get_block`] with `context = false`) is always
/// `None`.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextPattern {
    maskvalue: Option<PatternBlock>,
}

impl ContextPattern {
    /// An unconstrained context pattern (Java's no-arg constructor).
    pub fn new() -> Self {
        Self { maskvalue: None }
    }

    /// A context pattern constrained by `mv` (Java's `ContextPattern(PatternBlock mv)`).
    pub fn with_block(mv: PatternBlock) -> Self {
        Self { maskvalue: Some(mv) }
    }

    /// The context block this pattern constrains (Java's `getBlock()` no-arg overload).
    pub fn get_block(&self) -> Option<&PatternBlock> {
        self.maskvalue.as_ref()
    }
}

impl Default for ContextPattern {
    fn default() -> Self {
        Self::new()
    }
}

impl DisjointPattern for ContextPattern {
    fn get_block(&self, context: bool) -> Option<&PatternBlock> {
        if context {
            self.maskvalue.as_ref()
        } else {
            None
        }
    }
}

impl Pattern for ContextPattern {
    fn simplify_clone(&self) -> Box<dyn Pattern> {
        Box::new(ContextPattern {
            maskvalue: self.maskvalue.clone(),
        })
    }

    /// A `ContextPattern` places no constraint on instruction bits, so shifting the
    /// instruction-bit window does nothing (Java's `shiftInstruction` is an empty override).
    fn shift_instruction(&mut self, _sa: i32) {}

    fn always_true(&self) -> bool {
        self.maskvalue
            .as_ref()
            .map(PatternBlock::is_always_true)
            .unwrap_or(true)
    }

    fn always_false(&self) -> bool {
        self.maskvalue
            .as_ref()
            .map(PatternBlock::is_always_false)
            .unwrap_or(false)
    }

    /// A `ContextPattern` places no constraint on instruction bits, so its instruction-bit half
    /// is trivially always satisfied (Java's `alwaysInstructionTrue` unconditionally `true`).
    fn always_instruction_true(&self) -> bool {
        true
    }

    fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if let Some(b2) = (b as &dyn Any).downcast_ref::<ContextPattern>() {
            let a: Box<dyn DisjointPattern> = Box::new(self.clone());
            let b2: Box<dyn DisjointPattern> = Box::new(b2.clone());
            return Box::new(OrPatternImpl::with_pair(a, b2));
        }
        b.do_or(self, -sa)
    }

    fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if let Some(b2) = (b as &dyn Any).downcast_ref::<ContextPattern>() {
            let resblock = match (&self.maskvalue, &b2.maskvalue) {
                (Some(a), Some(b)) => Some(a.intersect(b)),
                _ => None,
            };
            return Box::new(ContextPattern { maskvalue: resblock });
        }
        b.do_and(self, -sa)
    }

    fn common_sub_pattern(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
        if let Some(b2) = (b as &dyn Any).downcast_ref::<ContextPattern>() {
            let resblock = match (&self.maskvalue, &b2.maskvalue) {
                (Some(a), Some(b)) => Some(a.common_sub_pattern(b)),
                _ => None,
            };
            return Box::new(ContextPattern { maskvalue: resblock });
        }
        b.common_sub_pattern(self, -sa)
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_CONTEXT_PAT)?;
        if let Some(maskvalue) = &self.maskvalue {
            maskvalue.encode(encoder)?;
        }
        encoder.close_element(ELEM_CONTEXT_PAT)?;
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
        let p = ContextPattern::new();
        assert!(p.get_block().is_none());
        assert!(DisjointPattern::get_block(&p, false).is_none());
    }

    #[test]
    fn with_block_stores_context_block_only() {
        let b = block(0xff, 0xaa);
        let p = ContextPattern::with_block(b.clone());
        assert_eq!(DisjointPattern::get_block(&p, true), Some(&b));
        assert!(DisjointPattern::get_block(&p, false).is_none());
    }

    #[test]
    fn simplify_clone_preserves_block() {
        let p = ContextPattern::with_block(block(0xff, 0xaa));
        let cloned = p.simplify_clone();
        assert!(cloned.always_true() == p.always_true());
    }

    #[test]
    fn shift_instruction_is_a_no_op() {
        let mut p = ContextPattern::with_block(block(0xff, 0xaa));
        let before = p.clone();
        p.shift_instruction(4);
        assert_eq!(p.maskvalue, before.maskvalue);
    }

    #[test]
    fn always_true_and_false_delegate_to_block_or_default_true_when_unconstrained() {
        assert!(ContextPattern::new().always_true());
        assert!(!ContextPattern::new().always_false());
        assert!(ContextPattern::with_block(PatternBlock::always_true()).always_true());
        assert!(ContextPattern::with_block(PatternBlock::always_false()).always_false());
    }

    #[test]
    fn always_instruction_true_is_unconditionally_true() {
        assert!(ContextPattern::new().always_instruction_true());
        assert!(ContextPattern::with_block(PatternBlock::always_false()).always_instruction_true());
    }

    #[test]
    fn do_and_with_another_context_pattern_intersects_blocks() {
        let a = ContextPattern::with_block(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        let b = ContextPattern::with_block(block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32));
        let result = a.do_and(&b, 0);
        let result = (result.as_ref() as &dyn Any)
            .downcast_ref::<ContextPattern>()
            .expect("do_and of two ContextPatterns returns a ContextPattern");
        assert_eq!(
            result.maskvalue,
            Some(a.maskvalue.as_ref().unwrap().intersect(b.maskvalue.as_ref().unwrap()))
        );
    }

    #[test]
    fn common_sub_pattern_with_another_context_pattern_combines_blocks() {
        let a = ContextPattern::with_block(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        let b = ContextPattern::with_block(block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32));
        let result = a.common_sub_pattern(&b, 0);
        let result = (result.as_ref() as &dyn Any)
            .downcast_ref::<ContextPattern>()
            .expect("common_sub_pattern of two ContextPatterns returns a ContextPattern");
        assert_eq!(
            result.maskvalue,
            Some(a.maskvalue.as_ref().unwrap().common_sub_pattern(b.maskvalue.as_ref().unwrap()))
        );
    }

    #[test]
    fn do_or_with_another_context_pattern_returns_or_pattern_with_both_disjuncts() {
        let a = ContextPattern::with_block(block(0xff00_0000u32 as i32, 0xaa00_0000u32 as i32));
        let b = ContextPattern::with_block(block(0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32));
        let result = a.do_or(&b, 0);
        assert_eq!(result.num_disjoint(), 2);
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }

        fn close_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.closed.push(elem_id.name);
            Ok(())
        }

        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_signed_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: i64,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: u64,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_element_and_block() {
        let p = ContextPattern::with_block(block(0xff, 0xaa));
        let mut encoder = RecordingEncoder::default();
        p.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["context_pat", "pat_block", "mask_word"]);
        assert_eq!(encoder.closed, vec!["mask_word", "pat_block", "context_pat"]);
    }

    #[test]
    fn encode_with_no_block_still_wraps_element() {
        let p = ContextPattern::new();
        let mut encoder = RecordingEncoder::default();
        p.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["context_pat"]);
    }
}
