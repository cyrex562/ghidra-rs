use super::varnode_tpl::VarnodeTpl;
use crate::program::model::pcode::{Decoder, DecoderError, ATTRIB_CODE, ELEM_NULL, ELEM_OP_TPL};

#[derive(Debug, Clone)]
pub struct OpTpl {
    pub opcode: i32,
    pub output: Option<VarnodeTpl>,
    pub input: Vec<VarnodeTpl>,
}

impl OpTpl {
    pub fn new() -> Self {
        Self {
            opcode: 0,
            output: None,
            input: Vec::new(),
        }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_OP_TPL)?;
        self.opcode = decoder.read_signed_integer_with_id(ATTRIB_CODE)? as i32;

        let outel = decoder.peek_element()?;
        if outel == ELEM_NULL.id {
            let null_el = decoder.open_element()?;
            decoder.close_element(null_el)?;
            self.output = None;
        } else {
            let mut vn = VarnodeTpl::new();
            vn.decode(decoder)?;
            self.output = Some(vn);
        }

        self.input.clear();
        while decoder.peek_element()? != 0 {
            let mut vn = VarnodeTpl::new();
            vn.decode(decoder)?;
            self.input.push(vn);
        }
        decoder.close_element(el)?;
        Ok(())
    }
}
