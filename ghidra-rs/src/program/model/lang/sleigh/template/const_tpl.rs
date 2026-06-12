use crate::program::model::address::AddressSpace;
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_PLUS, ATTRIB_S, ATTRIB_SPACE, ATTRIB_VAL, ELEM_CONST_CURSPACE,
    ELEM_CONST_CURSPACE_SIZE, ELEM_CONST_FLOWDEST, ELEM_CONST_FLOWDEST_SIZE, ELEM_CONST_FLOWREF,
    ELEM_CONST_FLOWREF_SIZE, ELEM_CONST_HANDLE, ELEM_CONST_NEXT, ELEM_CONST_NEXT2, ELEM_CONST_REAL,
    ELEM_CONST_RELATIVE, ELEM_CONST_SPACEID, ELEM_CONST_START,
};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstTplType {
    Real = 0,
    Handle = 1,
    JStart = 2,
    JNext = 3,
    JNext2 = 4,
    JCurSpace = 5,
    JCurSpaceSize = 6,
    SpaceId = 7,
    JRelative = 8,
    JFlowRef = 9,
    JFlowRefSize = 10,
    JFlowDest = 11,
    JFlowDestSize = 12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstTplSelect {
    VSpace = 0,
    VOffset = 1,
    VSize = 2,
    VOffsetPlus = 3,
}

#[derive(Debug, Clone)]
pub struct ConstTpl {
    pub tp: ConstTplType,
    pub value_real: u64,
    pub value_spaceid: Option<Arc<AddressSpace>>,
    pub handle_index: i16,
    pub select: Option<ConstTplSelect>,
}

impl ConstTpl {
    pub fn new() -> Self {
        Self {
            tp: ConstTplType::Real,
            value_real: 0,
            value_spaceid: None,
            handle_index: 0,
            select: None,
        }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        let el = decoder.open_element()?;
        if el == ELEM_CONST_REAL.id {
            self.tp = ConstTplType::Real;
            self.value_real = decoder.read_unsigned_integer_with_id(ATTRIB_VAL)?;
        } else if el == ELEM_CONST_HANDLE.id {
            self.tp = ConstTplType::Handle;
            self.handle_index = decoder.read_signed_integer_with_id(ATTRIB_VAL)? as i16;
            let s = decoder.read_signed_integer_with_id(ATTRIB_S)? as i32;
            self.select = match s {
                0 => Some(ConstTplSelect::VSpace),
                1 => Some(ConstTplSelect::VOffset),
                2 => Some(ConstTplSelect::VSize),
                3 => Some(ConstTplSelect::VOffsetPlus),
                _ => {
                    return Err(DecoderError::Generic(
                        "Bad handle selector encoding".to_string(),
                    ))
                }
            };
            if self.select == Some(ConstTplSelect::VOffsetPlus) {
                self.value_real = decoder.read_unsigned_integer_with_id(ATTRIB_PLUS)?;
            }
        } else if el == ELEM_CONST_START.id {
            self.tp = ConstTplType::JStart;
        } else if el == ELEM_CONST_NEXT.id {
            self.tp = ConstTplType::JNext;
        } else if el == ELEM_CONST_NEXT2.id {
            self.tp = ConstTplType::JNext2;
        } else if el == ELEM_CONST_CURSPACE.id {
            self.tp = ConstTplType::JCurSpace;
        } else if el == ELEM_CONST_CURSPACE_SIZE.id {
            self.tp = ConstTplType::JCurSpaceSize;
        } else if el == ELEM_CONST_SPACEID.id {
            self.tp = ConstTplType::SpaceId;
            self.value_spaceid = Some(decoder.read_space_with_id(ATTRIB_SPACE)?);
        } else if el == ELEM_CONST_RELATIVE.id {
            self.tp = ConstTplType::JRelative;
            self.value_real = decoder.read_unsigned_integer_with_id(ATTRIB_VAL)?;
        } else if el == ELEM_CONST_FLOWREF.id {
            self.tp = ConstTplType::JFlowRef;
        } else if el == ELEM_CONST_FLOWREF_SIZE.id {
            self.tp = ConstTplType::JFlowRefSize;
        } else if el == ELEM_CONST_FLOWDEST.id {
            self.tp = ConstTplType::JFlowDest;
        } else if el == ELEM_CONST_FLOWDEST_SIZE.id {
            self.tp = ConstTplType::JFlowDestSize;
        } else {
            return Err(DecoderError::Generic(
                "Bad encoding for ConstTpl".to_string(),
            ));
        }
        decoder.close_element(el)?;
        Ok(())
    }
}
