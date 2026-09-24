use super::const_tpl::ConstTpl;
use crate::program::model::pcode::{Decoder, DecoderError, Encoder, ELEM_HANDLE_TPL};
use std::io;

#[derive(Debug, Clone)]
pub struct HandleTpl {
    pub space: ConstTpl,
    pub size: ConstTpl,
    pub ptrspace: ConstTpl,
    pub ptroffset: ConstTpl,
    pub ptrsize: ConstTpl,
    pub temp_space: ConstTpl,
    pub temp_offset: ConstTpl,
}

impl HandleTpl {
    pub fn new() -> Self {
        Self {
            space: ConstTpl::new(),
            size: ConstTpl::new(),
            ptrspace: ConstTpl::new(),
            ptroffset: ConstTpl::new(),
            ptrsize: ConstTpl::new(),
            temp_space: ConstTpl::new(),
            temp_offset: ConstTpl::new(),
        }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_HANDLE_TPL)?;
        self.space.decode(decoder)?;
        self.size.decode(decoder)?;
        self.ptrspace.decode(decoder)?;
        self.ptroffset.decode(decoder)?;
        self.ptrsize.decode(decoder)?;
        self.temp_space.decode(decoder)?;
        self.temp_offset.decode(decoder)?;
        decoder.close_element(el)?;
        Ok(())
    }

    /// Remaps any handle-typed constants across every field through `handmap`.
    pub fn change_handle_index(&mut self, handmap: &[i32]) {
        self.space.change_handle_index(handmap);
        self.size.change_handle_index(handmap);
        self.ptrspace.change_handle_index(handmap);
        self.ptroffset.change_handle_index(handmap);
        self.ptrsize.change_handle_index(handmap);
        self.temp_space.change_handle_index(handmap);
        self.temp_offset.change_handle_index(handmap);
    }

    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_HANDLE_TPL)?;
        self.space.encode(encoder)?;
        self.size.encode(encoder)?;
        self.ptrspace.encode(encoder)?;
        self.ptroffset.encode(encoder)?;
        self.ptrsize.encode(encoder)?;
        self.temp_space.encode(encoder)?;
        self.temp_offset.encode(encoder)?;
        encoder.close_element(ELEM_HANDLE_TPL)
    }
}

impl Default for HandleTpl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::op_code::OpCode;
    use crate::program::model::pcode::{AttributeId, ElementId};

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.closed.push(elem_id.name);
            Ok(())
        }
        fn write_bool(&mut self, _a: AttributeId, _v: bool) -> io::Result<()> { Ok(()) }
        fn write_signed_integer(&mut self, _a: AttributeId, _v: i64) -> io::Result<()> { Ok(()) }
        fn write_unsigned_integer(&mut self, _a: AttributeId, _v: u64) -> io::Result<()> { Ok(()) }
        fn write_string(&mut self, _a: AttributeId, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_string_indexed(&mut self, _a: AttributeId, _i: i32, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_space(&mut self, _a: AttributeId, _s: &crate::program::model::address::AddressSpace) -> io::Result<()> { Ok(()) }
        fn write_space_indexed(&mut self, _a: AttributeId, _i: i32, _n: &str) -> io::Result<()> { Ok(()) }
        fn write_opcode(&mut self, _a: AttributeId, _o: OpCode) -> io::Result<()> { Ok(()) }
        fn write_opcode_ordinal(&mut self, _a: AttributeId, _o: i32) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn new_is_all_zero() {
        let h = HandleTpl::new();
        assert!(h.space.is_zero());
        assert!(h.size.is_zero());
    }

    #[test]
    fn change_handle_index_remaps_every_field() {
        let mut h = HandleTpl::new();
        h.space = ConstTpl {
            tp: crate::program::model::lang::sleigh::template::ConstTplType::Handle,
            value_real: 0,
            value_spaceid: None,
            handle_index: 0,
            select: Some(crate::program::model::lang::sleigh::template::ConstTplSelect::VSpace),
        };
        h.change_handle_index(&[9]);
        assert_eq!(h.space.handle_index, 9);
    }

    #[test]
    fn encode_wraps_all_seven_fields() {
        let h = HandleTpl::new();
        let mut encoder = RecordingEncoder::default();
        h.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened.first(), Some(&"handle_tpl"));
        assert_eq!(encoder.closed.last(), Some(&"handle_tpl"));
        // 1 outer handle_tpl + 7 const fields, each a const_real (all default-zero ConstTpls).
        assert_eq!(encoder.opened.len(), 8);
        assert_eq!(encoder.opened.iter().filter(|&&n| n == "const_real").count(), 7);
    }
}

/// Run-time resolution of an exported handle against a parsed instruction (the
/// `ghidra.app.plugin.processors.sleigh.template.HandleTpl` half of this shared type).
impl HandleTpl {
    /// Resolves this template into `hand` for the walker's position. Port of
    /// `HandleTpl.fix(FixedHandle, ParserWalker)`.
    ///
    /// # Errors
    /// A [`SleighError`](crate::program::model::lang::sleigh::walker::SleighError) if a piece
    /// of the template cannot be evaluated.
    pub fn fix(
        &self,
        hand: &mut crate::program::model::lang::sleigh::FixedHandle,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
    ) -> Result<(), crate::program::model::lang::sleigh::walker::SleighError> {
        use super::const_tpl::ConstTplType;
        use crate::program::model::address::AddressSpaceType;
        if self.ptrspace.tp == ConstTplType::Real {
            // The export is unstarred, but this doesn't mean the varnode being exported isn't
            // dynamic
            self.space.fillin_space(hand, walker)?;
            hand.size = self.size.fix(walker)? as i32;
            self.ptroffset.fillin_offset(hand, walker)?;
        } else {
            let space = self.space.fix_space(walker)?;
            hand.size = self.size.fix(walker)? as i32;
            hand.offset_offset = self.ptroffset.fix(walker)?;
            let offset_space = self.ptrspace.fix_space(walker)?;
            if offset_space.space_type() == AddressSpaceType::Constant {
                hand.offset_space = None; // Could have been, but wasn't
                hand.offset_offset = hand.offset_offset.wrapping_mul(space.unit_size() as i64);
                hand.offset_offset = space.truncate_offset(hand.offset_offset);
            } else {
                hand.offset_space = Some(offset_space);
                hand.offset_size = self.ptrsize.fix(walker)? as i32;
                hand.temp_space = Some(self.temp_space.fix_space(walker)?);
                hand.temp_offset = self.temp_offset.fix(walker)?;
            }
            hand.space = Some(space);
        }
        Ok(())
    }

    /// Adjusts a handle printed for operand `handle_index` when this template exports that
    /// operand as an address. Port of
    /// `HandleTpl.fixPrintPiece(FixedHandle, ParserWalker, int)`.
    ///
    /// # Errors
    /// A [`SleighError`](crate::program::model::lang::sleigh::walker::SleighError) if the
    /// exported space or size cannot be evaluated.
    pub fn fix_print_piece(
        &self,
        hand: &mut crate::program::model::lang::sleigh::FixedHandle,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
        handle_index: i32,
    ) -> Result<(), crate::program::model::lang::sleigh::walker::SleighError> {
        use super::const_tpl::ConstTplType;
        use crate::program::model::address::AddressSpaceType;
        if !hand.fixable {
            return Ok(());
        }
        if hand.space.as_ref().map(|s| s.space_type()) != Some(AddressSpaceType::Constant) {
            hand.fixable = false;
            return Ok(());
        }
        if self.space.tp == ConstTplType::SpaceId && self.space.is_unique_space() {
            hand.fixable = false;
            return Ok(());
        }
        if self.ptroffset.tp == ConstTplType::Handle
            && self.ptroffset.handle_index as i32 == handle_index
        {
            let space = self.space.fix_space(walker)?;
            hand.offset_offset = (space.unit_size() as i64).wrapping_mul(hand.offset_offset);
            hand.size = self.size.fix(walker)? as i32;
            hand.space = Some(space);
        } else {
            hand.fixable = false;
        }
        Ok(())
    }
}
