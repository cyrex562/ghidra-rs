use crate::program::model::lang::sleigh::walker::ParserWalker;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::ids::*;

#[derive(Debug, Clone)]
pub enum PatternExpression {
    TokenField(TokenField),
    ContextField(ContextField),
    Constant(i64),
    Operand(OperandValue),
    StartInstruction,
    EndInstruction,
    Next2Instruction,
    Plus(Box<PatternExpression>, Box<PatternExpression>),
    Sub(Box<PatternExpression>, Box<PatternExpression>),
    Mult(Box<PatternExpression>, Box<PatternExpression>),
    LeftShift(Box<PatternExpression>, Box<PatternExpression>),
    RightShift(Box<PatternExpression>, Box<PatternExpression>),
    And(Box<PatternExpression>, Box<PatternExpression>),
    Or(Box<PatternExpression>, Box<PatternExpression>),
    Xor(Box<PatternExpression>, Box<PatternExpression>),
    Div(Box<PatternExpression>, Box<PatternExpression>),
    Minus(Box<PatternExpression>),
    Not(Box<PatternExpression>),
}

impl PatternExpression {
    pub fn get_value(&self, walker: &ParserWalker) -> Result<i64, MemoryAccessException> {
        match self {
            Self::TokenField(f) => f.get_value(walker),
            Self::ContextField(f) => f.get_value(walker),
            Self::Constant(val) => Ok(*val),
            Self::Operand(o) => o.get_value(walker),
            Self::StartInstruction => Ok(walker.context.addr.offset() as i64),
            Self::EndInstruction => Ok(walker.context.naddr.offset() as i64),
            Self::Next2Instruction => Ok(walker.context.n2addr.offset() as i64),
            Self::Plus(l, r) => Ok(l.get_value(walker)? + r.get_value(walker)?),
            Self::Sub(l, r) => Ok(l.get_value(walker)? - r.get_value(walker)?),
            Self::Mult(l, r) => Ok(l.get_value(walker)? * r.get_value(walker)?),
            Self::LeftShift(l, r) => Ok(l.get_value(walker)? << r.get_value(walker)?),
            Self::RightShift(l, r) => Ok(l.get_value(walker)? >> r.get_value(walker)?),
            Self::And(l, r) => Ok(l.get_value(walker)? & r.get_value(walker)?),
            Self::Or(l, r) => Ok(l.get_value(walker)? | r.get_value(walker)?),
            Self::Xor(l, r) => Ok(l.get_value(walker)? ^ r.get_value(walker)?),
            Self::Div(l, r) => {
                let divisor = r.get_value(walker)?;
                if divisor == 0 {
                    Ok(0) // Consistent with Ghidra's behavior in some cases, or throw?
                } else {
                    Ok(l.get_value(walker)? / divisor)
                }
            }
            Self::Minus(u) => Ok(-u.get_value(walker)?),
            Self::Not(u) => Ok(!u.get_value(walker)?),
        }
    }

    pub fn decode(decoder: &dyn Decoder, lang: &SleighLanguage) -> Result<Self, DecoderError> {
        let el = decoder.peek_element()?;
        if el == ELEM_TOKENFIELD.id {
            Ok(Self::TokenField(TokenField::decode(decoder)?))
        } else if el == ELEM_CONTEXTFIELD.id {
            Ok(Self::ContextField(ContextField::decode(decoder)?))
        } else if el == ELEM_INTB.id {
            let subel = decoder.open_element()?;
            let val = decoder.read_signed_integer_with_id(ATTRIB_VAL)?;
            decoder.close_element(subel)?;
            Ok(Self::Constant(val))
        } else if el == ELEM_OPERAND_EXP.id {
            Ok(Self::Operand(OperandValue::decode(decoder)?))
        } else if el == ELEM_START_EXP.id {
            let subel = decoder.open_element()?;
            decoder.close_element(subel)?;
            Ok(Self::StartInstruction)
        } else if el == ELEM_END_EXP.id {
            let subel = decoder.open_element()?;
            decoder.close_element(subel)?;
            Ok(Self::EndInstruction)
        } else if el == ELEM_NEXT2_EXP.id {
            let subel = decoder.open_element()?;
            decoder.close_element(subel)?;
            Ok(Self::Next2Instruction)
        } else if el == ELEM_PLUS_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Plus(l, r))
        } else if el == ELEM_SUB_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Sub(l, r))
        } else if el == ELEM_MULT_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Mult(l, r))
        } else if el == ELEM_LSHIFT_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::LeftShift(l, r))
        } else if el == ELEM_RSHIFT_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::RightShift(l, r))
        } else if el == ELEM_AND_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::And(l, r))
        } else if el == ELEM_OR_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Or(l, r))
        } else if el == ELEM_XOR_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Xor(l, r))
        } else if el == ELEM_DIV_EXP.id {
            let subel = decoder.open_element()?;
            let l = Box::new(Self::decode(decoder, lang)?);
            let r = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Div(l, r))
        } else if el == ELEM_MINUS_EXP.id {
            let subel = decoder.open_element()?;
            let u = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Minus(u))
        } else if el == ELEM_NOT_EXP.id {
            let subel = decoder.open_element()?;
            let u = Box::new(Self::decode(decoder, lang)?);
            decoder.close_element(subel)?;
            Ok(Self::Not(u))
        } else {
            Err(DecoderError::Generic(format!(
                "Unknown expression type: {}",
                el
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenField {
    pub bigendian: bool,
    pub signbit: bool,
    pub bitstart: i32,
    pub bitend: i32,
    pub bytestart: i32,
    pub byteend: i32,
    pub shift: i32,
}

impl TokenField {
    pub fn get_value(&self, walker: &ParserWalker) -> Result<i64, MemoryAccessException> {
        let mut res = self.get_instruction_bytes(walker)?;
        res >>= self.shift;
        if self.signbit {
            Ok(Self::sign_extend(res, self.bitend - self.bitstart))
        } else {
            Ok(Self::zero_extend(res, self.bitend - self.bitstart))
        }
    }

    fn get_instruction_bytes(&self, walker: &ParserWalker) -> Result<i64, MemoryAccessException> {
        let mut res = 0i64;
        let size = (self.byteend - self.bytestart + 1) as i32;
        let mut tmpsize = size;
        let mut bs = self.bytestart;

        while tmpsize >= 4 {
            let tmp = walker.get_instruction_bits(bs * 8, 32)?;
            res <<= 32;
            res |= (tmp as u64 & 0xffffffff) as i64;
            bs += 4;
            tmpsize -= 4;
        }
        if tmpsize > 0 {
            let tmp = walker.get_instruction_bits(bs * 8, tmpsize * 8)?;
            res <<= 8 * tmpsize;
            res |= (tmp as u64 & 0xffffffff) as i64;
        }
        if !self.bigendian {
            res = Self::byte_swap(res, size);
        }
        Ok(res)
    }

    fn sign_extend(mut val: i64, bit: i32) -> i64 {
        let mask = (!0i64) << bit;
        if ((val >> bit) & 1) != 0 {
            val |= mask;
        } else {
            val &= !mask;
        }
        val
    }

    fn zero_extend(val: i64, bit: i32) -> i64 {
        let mut mask = (!0i64) << bit;
        mask <<= 1;
        val & !mask
    }

    fn byte_swap(mut val: i64, mut size: i32) -> i64 {
        let mut res = 0i64;
        while size > 0 {
            res <<= 8;
            res |= val & 0xff;
            val >>= 8;
            size -= 1;
        }
        res
    }

    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.open_element_with_id(ELEM_TOKENFIELD)?;
        let bigendian = decoder.read_bool_with_id(ATTRIB_BIGENDIAN)?;
        let signbit = decoder.read_bool_with_id(ATTRIB_SIGNBIT)?;
        let bitstart = decoder.read_signed_integer_with_id(ATTRIB_STARTBIT)? as i32;
        let bitend = decoder.read_signed_integer_with_id(ATTRIB_ENDBIT)? as i32;
        let bytestart = decoder.read_signed_integer_with_id(ATTRIB_STARTBYTE)? as i32;
        let byteend = decoder.read_signed_integer_with_id(ATTRIB_ENDBYTE)? as i32;
        let shift = decoder.read_signed_integer_with_id(ATTRIB_SHIFT)? as i32;
        decoder.close_element(el)?;

        Ok(Self {
            bigendian,
            signbit,
            bitstart,
            bitend,
            bytestart,
            byteend,
            shift,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ContextField {
    pub signbit: bool,
    pub bitstart: i32,
    pub bitend: i32,
    pub bytestart: i32,
    pub byteend: i32,
    pub shift: i32,
}

impl ContextField {
    pub fn get_value(&self, walker: &ParserWalker) -> Result<i64, MemoryAccessException> {
        let mut res =
            walker.get_context_bits(self.bitstart, self.bitend - self.bitstart + 1) as i64;
        if self.signbit {
            res = TokenField::sign_extend(res, self.bitend - self.bitstart);
        }
        Ok(res)
    }

    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.open_element_with_id(ELEM_CONTEXTFIELD)?;
        let signbit = decoder.read_bool_with_id(ATTRIB_SIGNBIT)?;
        let bitstart = decoder.read_signed_integer_with_id(ATTRIB_STARTBIT)? as i32;
        let bitend = decoder.read_signed_integer_with_id(ATTRIB_ENDBIT)? as i32;
        let bytestart = decoder.read_signed_integer_with_id(ATTRIB_STARTBYTE)? as i32;
        let byteend = decoder.read_signed_integer_with_id(ATTRIB_ENDBYTE)? as i32;
        let shift = decoder.read_signed_integer_with_id(ATTRIB_SHIFT)? as i32;
        decoder.close_element(el)?;

        Ok(Self {
            signbit,
            bitstart,
            bitend,
            bytestart,
            byteend,
            shift,
        })
    }
}

#[derive(Debug, Clone)]
pub struct OperandValue {
    pub index: i32,
    pub constructor_id: i32,
}

impl OperandValue {
    pub fn get_value(&self, walker: &ParserWalker) -> Result<i64, MemoryAccessException> {
        // Resolve operand's value.
        // In Ghidra, this usually calls TripleSymbol.getValue() or gets it from a handle.
        // For simple PatternExpressions, we look at the handle in the walker.
        if let Some(h) = walker.get_fixed_handle(self.index as usize) {
            Ok(h.offset_offset as i64)
        } else {
            Ok(0)
        }
    }

    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.open_element_with_id(ELEM_OPERAND_EXP)?;
        let index = decoder.read_signed_integer_with_id(ATTRIB_INDEX)? as i32;
        let constructor_id = decoder.read_signed_integer_with_id(ATTRIB_ID)? as i32;
        decoder.close_element(el)?;

        Ok(Self {
            index,
            constructor_id,
        })
    }
}
