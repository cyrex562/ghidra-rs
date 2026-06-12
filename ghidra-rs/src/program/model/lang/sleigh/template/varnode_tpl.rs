use super::const_tpl::ConstTpl;
use crate::program::model::pcode::{Decoder, DecoderError, ELEM_VARNODE_TPL};

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
}
