use super::const_tpl::{ConstTpl, ConstTplSelect, ConstTplType};
use crate::program::model::pcode::{Decoder, DecoderError, Encoder, ELEM_VARNODE_TPL};
use std::io;

/// Models `ghidra.pcodeCPort.semantics.VarnodeTpl`. Deliberately shared between the pcodeCPort
/// compiler and sleigh runtime representations -- both need the same .sla-serializable template
/// format (see `decompiler::slghsymbol::specific_symbol::SpecificSymbol::get_varnode`'s callers).
///
/// Java's `location: Location` field is stored but never read by any of `VarnodeTpl`'s own
/// methods (only used for error reporting by callers that already have their own location in
/// hand) -- deliberately NOT ported as a struct field: every existing construction site across
/// this crate (pcode formatting, `op_tpl_walker`, `sleigh_instruction_prototype`, ...) already
/// builds a bare `VarnodeTpl { space, offset, size }` via struct literal with no location, and
/// adding a mandatory field would force touching all of them just to carry data nothing here
/// reads. `unnamed_flag`/`is_local_temp()`/`transfer(&[HandleTpl])` are also not ported: Java
/// only uses those from `MacroBuilder`/`PcodeCompile`/`SleighCompile`'s macro-expansion pipeline,
/// a separate, not-yet-relevant feature area.
///
/// `with_handle` (added while sizing `OperandSymbol`'s own port gap, 2026-09) is Java's
/// `VarnodeTpl(Location, int hand, boolean zerosize)` minus the unused location parameter --
/// used by `OperandSymbol.getVarnode()` for both its "definite constant handle" and "possible
/// dynamic handle" branches. `with_fields` (added while sizing `VarnodeSymbol`'s own port gap,
/// 2026-09) is the remaining ported constructor, `VarnodeTpl(Location, ConstTpl, ConstTpl,
/// ConstTpl)`, likewise minus location -- used by `VarnodeSymbol.getVarnode()` for a fixed
/// global varnode. Only the clone constructor (`VarnodeTpl(Location, VarnodeTpl)`, redundant
/// with `#[derive(Clone)]`) remains unported.
#[derive(Debug, Clone)]
pub struct VarnodeTpl {
    pub space: ConstTpl,
    pub offset: ConstTpl,
    pub size: ConstTpl,
}

impl VarnodeTpl {
    pub fn new() -> Self {
        Self {
            space: ConstTpl::new(),
            offset: ConstTpl::new(),
            size: ConstTpl::new(),
        }
    }

    /// Builds a varnode from a handle index (Java's `VarnodeTpl(Location, int hand, boolean
    /// zerosize)`, minus the unused `location` parameter -- see this type's own doc comment).
    /// `space`/`offset` always resolve dynamically through the handle at `hand`; `size` does too
    /// unless `zerosize` is set, in which case it's pinned to the real constant `0`.
    pub fn with_handle(hand: i32, zerosize: bool) -> Self {
        let handle_const = |select: ConstTplSelect| ConstTpl {
            tp: ConstTplType::Handle,
            value_real: 0,
            value_spaceid: None,
            handle_index: hand as i16,
            select: Some(select),
        };
        let size = if zerosize {
            ConstTpl {
                tp: ConstTplType::Real,
                value_real: 0,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            }
        } else {
            handle_const(ConstTplSelect::VSize)
        };
        Self {
            space: handle_const(ConstTplSelect::VSpace),
            offset: handle_const(ConstTplSelect::VOffset),
            size,
        }
    }

    /// Builds a varnode directly from its space/offset/size constants (Java's `VarnodeTpl
    /// (Location, ConstTpl sp, ConstTpl off, ConstTpl sz)`, minus the unused `location`
    /// parameter -- see this type's own doc comment). Used by `VarnodeSymbol.getVarnode()` for a
    /// fixed global varnode (a real, constant space/offset/size, not resolved through a handle).
    pub fn with_fields(space: ConstTpl, offset: ConstTpl, size: ConstTpl) -> Self {
        Self { space, offset, size }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_VARNODE_TPL)?;
        self.space.decode(decoder)?;
        self.offset.decode(decoder)?;
        self.size.decode(decoder)?;
        decoder.close_element(el)?;
        Ok(())
    }

    /// Returns true if this varnode's size is a zero-valued real constant.
    pub fn is_zero_size(&self) -> bool {
        self.size.is_zero()
    }

    /// Remaps any handle-typed constants (space/offset/size) through `handmap`.
    pub fn change_handle_index(&mut self, handmap: &[i32]) {
        self.space.change_handle_index(handmap);
        self.offset.change_handle_index(handmap);
        self.size.change_handle_index(handmap);
    }

    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_VARNODE_TPL)?;
        self.space.encode(encoder)?;
        self.offset.encode(encoder)?;
        self.size.encode(encoder)?;
        encoder.close_element(ELEM_VARNODE_TPL)
    }
}

impl Default for VarnodeTpl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::op_code::OpCode;
    use crate::program::model::pcode::{AttributeId, ElementId};

    #[test]
    fn new_is_all_zero_real_constants() {
        let vn = VarnodeTpl::new();
        assert_eq!(vn.space.tp, ConstTplType::Real);
        assert_eq!(vn.offset.tp, ConstTplType::Real);
        assert_eq!(vn.size.tp, ConstTplType::Real);
        assert!(vn.is_zero_size());
    }

    #[test]
    fn with_handle_resolves_space_and_offset_through_the_handle() {
        let vn = VarnodeTpl::with_handle(3, false);
        assert_eq!(vn.space.tp, ConstTplType::Handle);
        assert_eq!(vn.space.handle_index, 3);
        assert_eq!(vn.space.select, Some(ConstTplSelect::VSpace));
        assert_eq!(vn.offset.tp, ConstTplType::Handle);
        assert_eq!(vn.offset.handle_index, 3);
        assert_eq!(vn.offset.select, Some(ConstTplSelect::VOffset));
    }

    #[test]
    fn with_handle_size_resolves_through_the_handle_unless_zerosize() {
        let dynamic = VarnodeTpl::with_handle(3, false);
        assert_eq!(dynamic.size.tp, ConstTplType::Handle);
        assert_eq!(dynamic.size.select, Some(ConstTplSelect::VSize));
        assert!(!dynamic.is_zero_size());

        let fixed = VarnodeTpl::with_handle(3, true);
        assert_eq!(fixed.size.tp, ConstTplType::Real);
        assert_eq!(fixed.size.value_real, 0);
        assert!(fixed.is_zero_size());
    }

    #[test]
    fn change_handle_index_remaps_every_handle_typed_field() {
        let mut vn = VarnodeTpl::with_handle(0, false);
        vn.change_handle_index(&[5]);
        assert_eq!(vn.space.handle_index, 5);
        assert_eq!(vn.offset.handle_index, 5);
        assert_eq!(vn.size.handle_index, 5);
    }

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
    fn encode_wraps_space_offset_size_in_a_varnode_tpl_element() {
        let vn = VarnodeTpl::with_handle(2, true);
        let mut encoder = RecordingEncoder::default();
        vn.encode(&mut encoder).unwrap();

        // The outer varnode_tpl element, plus one const_handle for space/offset and one
        // const_real for the zero-pinned size.
        assert_eq!(encoder.opened.first(), Some(&"varnode_tpl"));
        assert_eq!(encoder.closed.last(), Some(&"varnode_tpl"));
        assert_eq!(encoder.opened.len(), encoder.closed.len());
        assert_eq!(encoder.opened.iter().filter(|&&n| n == "const_handle").count(), 2);
        assert_eq!(encoder.opened.iter().filter(|&&n| n == "const_real").count(), 1);
    }
}

/// Run-time queries of a varnode template against a parsed instruction (the
/// `ghidra.app.plugin.processors.sleigh.template.VarnodeTpl` half of this shared type).
impl VarnodeTpl {
    /// Port of `VarnodeTpl.isDynamic(ParserWalker)`: whether the offset resolves through a
    /// dynamic (pointer) handle. Only the offset is checked, as in Java: if any piece is
    /// dynamic, the offset is.
    pub fn is_dynamic(
        &self,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
    ) -> bool {
        if self.offset.tp != ConstTplType::Handle {
            return false;
        }
        walker
            .get_fixed_handle(self.offset.handle_index as usize)
            .offset_space
            .is_some()
    }

    /// Port of `VarnodeTpl.isRelative()`: whether the offset is a label-relative reference.
    pub fn is_relative(&self) -> bool {
        self.offset.tp == ConstTplType::JRelative
    }
}
