use super::const_tpl::ConstTpl;
use crate::program::model::pcode::{Decoder, DecoderError, ELEM_HANDLE_TPL};

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
}
