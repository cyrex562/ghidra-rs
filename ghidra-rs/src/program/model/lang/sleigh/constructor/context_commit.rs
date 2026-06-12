use crate::program::model::lang::sleigh::symbol::{SleighSymbol, TripleSymbol};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_ID, ATTRIB_MASK, ATTRIB_NUMBER, ELEM_COMMIT,
};

#[derive(Debug, Clone)]
pub struct ContextCommit {
    pub sym: Option<TripleSymbol>,
    pub num: i32,
    pub mask: u32,
}

impl ContextCommit {
    pub fn new() -> Self {
        Self {
            sym: None,
            num: 0,
            mask: 0,
        }
    }

    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_COMMIT)?;
        let id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32;

        let sym = lang.get_symbol_table().find_symbol(id);
        if let Some(SleighSymbol::Triple(ts)) = sym {
            self.sym = Some(ts.clone());
        } else {
            return Err(DecoderError::Generic(format!(
                "ContextCommit: Symbol ID {} is not a TripleSymbol",
                id
            )));
        }

        self.num = decoder.read_signed_integer_with_id(ATTRIB_NUMBER)? as i32;
        self.mask = decoder.read_unsigned_integer_with_id(ATTRIB_MASK)? as u32;
        decoder.close_element(el)?;
        Ok(())
    }
}
