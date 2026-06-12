use crate::program::model::lang::sleigh::expression::PatternExpression;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_I, ATTRIB_MASK, ATTRIB_SHIFT, ELEM_CONTEXT_OP,
};

#[derive(Debug, Clone)]
pub struct ContextOp {
    pub patexp: PatternExpression,
    pub num: i32,
    pub mask: u32,
    pub shift: i32,
}

impl ContextOp {
    pub fn new() -> Self {
        Self {
            patexp: PatternExpression::Constant(0),
            num: 0,
            mask: 0,
            shift: 0,
        }
    }

    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_CONTEXT_OP)?;
        self.num = decoder.read_signed_integer_with_id(ATTRIB_I)? as i32;
        self.shift = decoder.read_signed_integer_with_id(ATTRIB_SHIFT)? as i32;
        self.mask = decoder.read_unsigned_integer_with_id(ATTRIB_MASK)? as u32;
        self.patexp = PatternExpression::decode(decoder, lang)?;
        decoder.close_element(el)?;
        Ok(())
    }
}
