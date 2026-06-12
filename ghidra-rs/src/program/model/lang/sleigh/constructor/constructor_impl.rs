use crate::program::model::lang::sleigh::constructor::ContextChange;
use crate::program::model::lang::sleigh::symbol::{OperandSymbol, SleighSymbol};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_FIRST, ATTRIB_ID, ATTRIB_LENGTH, ATTRIB_LINE, ATTRIB_PARENT,
    ATTRIB_PIECE, ATTRIB_SOURCE, ELEM_COMMIT, ELEM_CONSTRUCTOR, ELEM_CONTEXT_OP, ELEM_OPER,
    ELEM_OPPRINT, ELEM_PRINT,
};
use std::sync::Arc;

pub struct Constructor {
    pub parent_id: i32,
    pub first_whitespace: i32,
    pub minimum_length: i32,
    pub lineno: i32,
    pub operands: Vec<Arc<OperandSymbol>>,
    pub print_pieces: Vec<String>,
    pub context: Vec<ContextChange>,
    pub templ: Option<ConstructTpl>,
    pub named_templ: Vec<Option<ConstructTpl>>,
    pub flowthru_index: i32,
}

impl Constructor {
    pub fn new() -> Self {
        Self {
            parent_id: 0,
            first_whitespace: -1,
            minimum_length: 0,
            lineno: 0,
            operands: Vec::new(),
            print_pieces: Vec::new(),
            context: Vec::new(),
            templ: None,
            named_templ: Vec::new(),
            flowthru_index: -1,
        }
    }

    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        sleigh: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_CONSTRUCTOR)?;

        self.parent_id = decoder.read_unsigned_integer_with_id(ATTRIB_PARENT)? as i32;
        self.first_whitespace = decoder.read_signed_integer_with_id(ATTRIB_FIRST)? as i32;
        self.minimum_length = decoder.read_signed_integer_with_id(ATTRIB_LENGTH)? as i32;
        let _src_line = decoder.read_signed_integer_with_id(ATTRIB_SOURCE)? as i32;
        self.lineno = decoder.read_signed_integer_with_id(ATTRIB_LINE)? as i32;

        self.operands.clear();
        self.print_pieces.clear();
        self.context.clear();
        self.templ = None;
        self.named_templ.clear();

        while decoder.peek_element()? != 0 {
            let subel = decoder.peek_element()?;
            if subel == ELEM_OPER.id {
                let subel_open = decoder.open_element()?;
                let my_id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32;
                let sym = sleigh.get_symbol_table().find_symbol(my_id);
                if let Some(SleighSymbol::Operand(op)) = sym {
                    self.operands.push(Arc::new(op.clone()));
                } else {
                    return Err(DecoderError::Generic(format!(
                        "Constructor: Symbol ID {} is not an OperandSymbol",
                        my_id
                    )));
                }
                decoder.close_element_skipping(subel_open)?;
            } else if subel == ELEM_PRINT.id {
                let subel_open = decoder.open_element()?;
                self.print_pieces
                    .push(decoder.read_string_with_id(ATTRIB_PIECE)?);
                decoder.close_element_skipping(subel_open)?;
            } else if subel == ELEM_OPPRINT.id {
                let subel_open = decoder.open_element()?;
                let my_id = decoder.read_signed_integer_with_id(ATTRIB_ID)? as i32;
                let mut operstring = String::from("\n");
                operstring.push((b'A' + my_id as u8) as char);
                self.print_pieces.push(operstring);
                decoder.close_element_skipping(subel_open)?;
            } else if subel == ELEM_CONTEXT_OP.id {
                let mut c_op = super::ContextOp::new();
                c_op.decode(decoder, sleigh)?;
                self.context.push(ContextChange::Op(c_op));
            } else if subel == ELEM_COMMIT.id {
                let mut c_commit = super::ContextCommit::new();
                c_commit.decode(decoder, sleigh)?;
                self.context.push(ContextChange::Commit(c_commit));
            } else {
                let mut curtempl = ConstructTpl::new();
                let section_id = curtempl.decode(decoder)?;
                if section_id < 0 {
                    if self.templ.is_some() {
                        return Err(DecoderError::Generic(
                            "Duplicate main template section".to_string(),
                        ));
                    }
                    self.templ = Some(curtempl);
                } else {
                    let sid = section_id as usize;
                    if self.named_templ.len() <= sid {
                        self.named_templ.resize(sid + 1, None);
                    }
                    if self.named_templ[sid].is_some() {
                        return Err(DecoderError::Generic(
                            "Duplicate named template section".to_string(),
                        ));
                    }
                    self.named_templ[sid] = Some(curtempl);
                }
            }
        }

        if self.print_pieces.len() == 1
            && self.print_pieces[0].len() >= 2
            && self.print_pieces[0].starts_with('\n')
        {
            self.flowthru_index = (self.print_pieces[0].as_bytes()[1] - b'A') as i32;
        } else {
            self.flowthru_index = -1;
        }

        decoder.close_element(el)?;
        Ok(())
    }
}
