pub mod const_tpl;
pub mod handle_tpl;
pub mod op_tpl;
pub mod varnode_tpl;

use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_LABELS, ATTRIB_SECTION, ELEM_CONSTRUCT_TPL, ELEM_NULL,
};
pub use const_tpl::{ConstTpl, ConstTplSelect, ConstTplType};
pub use handle_tpl::HandleTpl;
pub use op_tpl::OpTpl;
pub use varnode_tpl::VarnodeTpl;

#[derive(Debug, Clone)]
pub struct ConstructTpl {
    pub num_labels: i32,
    pub vec: Vec<OpTpl>,
    pub result: Option<HandleTpl>,
}

impl ConstructTpl {
    pub fn new() -> Self {
        Self {
            num_labels: 0,
            vec: Vec::new(),
            result: None,
        }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<i32, DecoderError> {
        let mut section_id = -1;
        self.num_labels = 0;
        let el = decoder.open_element_with_id(ELEM_CONSTRUCT_TPL)?;

        loop {
            let attr = decoder.get_next_attribute_id()?;
            if attr == 0 {
                break;
            }
            if attr == ATTRIB_LABELS.id {
                self.num_labels = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_SECTION.id {
                section_id = decoder.read_signed_integer()? as i32;
            }
        }

        let hand_el = decoder.peek_element()?;
        if hand_el == ELEM_NULL.id {
            let null_el = decoder.open_element()?;
            decoder.close_element(null_el)?;
            self.result = None;
        } else {
            let mut hand = HandleTpl::new();
            hand.decode(decoder)?;
            self.result = Some(hand);
        }

        self.vec.clear();
        while decoder.peek_element()? != 0 {
            let mut op = OpTpl::new();
            op.decode(decoder)?;
            self.vec.push(op);
        }
        decoder.close_element(el)?;
        Ok(section_id)
    }
}
