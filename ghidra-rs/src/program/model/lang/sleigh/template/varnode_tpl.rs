use super::const_tpl::ConstTpl;
use crate::program::model::pcode::{Decoder, DecoderError, Encoder, ELEM_VARNODE_TPL};
use std::io;

/// Models `ghidra.pcodeCPort.semantics.VarnodeTpl`. Deliberately shared between the pcodeCPort
/// compiler and sleigh runtime representations -- both need the same .sla-serializable template
/// format (see `decompiler::slghsymbol::specific_symbol::SpecificSymbol::get_varnode`'s callers).
///
/// INCOMPLETE relative to the real class (found while sizing `OperandSymbol`'s own port gap,
/// 2026-09): missing the `location: Location` field, `unnamed_flag`, `is_local_temp()`,
/// `transfer(&[HandleTpl])`, `set_offset`/`set_relative`/`set_size`/`is_relative`, and three of
/// Java's five constructors -- notably `VarnodeTpl(Location, int hand, boolean zerosize)`
/// (builds a `ConstTpl::const_type::handle`-typed space/offset/size from a handle index, used by
/// `OperandSymbol.getVarnode()` for both the "definite constant handle" and "possible dynamic
/// handle" cases).
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
