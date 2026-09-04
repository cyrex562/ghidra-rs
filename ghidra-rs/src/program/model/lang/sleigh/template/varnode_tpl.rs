use super::const_tpl::ConstTpl;
use crate::program::model::pcode::{Decoder, DecoderError, Encoder, ELEM_VARNODE_TPL};
use std::io;

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
