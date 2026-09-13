use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
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
    /// Returns the left/right operands if this is one of the binary-operator variants (i.e. this
    /// crate's flattened counterpart to a `BinaryExpression` subclass instance), `None`
    /// otherwise. Mirrors `BinaryExpression.getLeft()`/`getRight()`, used generically by
    /// [`AbstractBinaryExpressionSolver`](
    /// crate::app::plugin::assembler::sleigh::expr::AbstractBinaryExpressionSolver) across every
    /// binary operator without needing a distinct `BinaryExpression` type to range over.
    pub fn binary_operands(&self) -> Option<(&PatternExpression, &PatternExpression)> {
        match self {
            Self::Plus(l, r)
            | Self::Sub(l, r)
            | Self::Mult(l, r)
            | Self::LeftShift(l, r)
            | Self::RightShift(l, r)
            | Self::And(l, r)
            | Self::Or(l, r)
            | Self::Xor(l, r)
            | Self::Div(l, r) => Some((l, r)),
            _ => None,
        }
    }

    /// The smallest value this expression can take on.
    ///
    /// Port of `ghidra.app.plugin.processors.sleigh.expression.PatternValue.minValue()`.
    /// `PatternValue` is the abstract subclass of `PatternExpression` that `TokenField`,
    /// `ContextField`, `ConstantValue`, `OperandValue`, `StartInstructionValue`,
    /// `EndInstructionValue`, and `Next2InstructionValue` extend (i.e. every leaf value, but
    /// none of the `BinaryExpression`/`UnaryExpression` operator subclasses) -- see those
    /// classes' `extends` clauses under
    /// `orig_src/.../ghidra/app/plugin/processors/sleigh/expression/`. Since this crate
    /// flattens the whole `PatternExpression` hierarchy into one enum (see the type's own
    /// docs/callers) rather than modeling `PatternValue` as a distinct type, that leaf-only
    /// restriction is enforced here at runtime instead of compile time: calling `min_value`/
    /// `max_value` on one of the operator variants returns `Err`, mirroring how Java simply
    /// does not expose `minValue`/`maxValue` through a `PatternExpression`-typed reference to a
    /// `BinaryExpression`/`UnaryExpression` (the methods aren't declared there at all).
    ///
    /// Per `PatternValue`'s own class comment, "None of the functionality is needed for the
    /// disassembly interface (only for the compiler interface), but we preserve the structure" --
    /// this crate has no SLEIGH compiler built on top of this package, so `min_value`/
    /// `max_value` exist here purely for structural fidelity with the Java source.
    pub fn min_value(&self) -> Result<i64, SleighException> {
        match self {
            Self::Constant(val) => Ok(*val),
            Self::TokenField(_) | Self::ContextField(_) => Ok(0),
            Self::StartInstruction | Self::EndInstruction | Self::Next2Instruction => Ok(0),
            // Java: `OperandValue.minValue()` unconditionally throws
            // `new SleighException("Operand used in pattern expression")`, regardless of the
            // operand's index or constructor -- faithfully reproduced rather than computing a
            // bound from the underlying symbol.
            Self::Operand(_) => Err(SleighException::with_message(
                "Operand used in pattern expression",
            )),
            _ => Err(SleighException::with_message(
                "not a PatternValue: minValue/maxValue is only declared on PatternExpression's \
                 leaf (non-operator) variants",
            )),
        }
    }

    /// The largest value this expression can take on.
    ///
    /// Port of `ghidra.app.plugin.processors.sleigh.expression.PatternValue.maxValue()`. See
    /// [`Self::min_value`] for the shared design notes on why this is a fallible method on the
    /// flattened enum rather than a method on a distinct `PatternValue` type.
    pub fn max_value(&self) -> Result<i64, SleighException> {
        match self {
            Self::Constant(val) => Ok(*val),
            Self::TokenField(f) => Ok(Self::field_max_value(f.bitstart, f.bitend)),
            Self::ContextField(f) => Ok(Self::field_max_value(f.bitstart, f.bitend)),
            Self::StartInstruction | Self::EndInstruction | Self::Next2Instruction => Ok(0),
            Self::Operand(_) => Err(SleighException::with_message(
                "Operand used in pattern expression",
            )),
            _ => Err(SleighException::with_message(
                "not a PatternValue: minValue/maxValue is only declared on PatternExpression's \
                 leaf (non-operator) variants",
            )),
        }
    }

    /// Shared bit-width-to-max-value computation used by both `TokenField.maxValue()` and
    /// `ContextField.maxValue()` in Java, which are textually identical:
    /// ```java
    /// long res = -1;
    /// res <<= (bitend - bitstart);
    /// res <<= 1;
    /// return ~res;
    /// ```
    /// Deliberately performed as two separate shifts (rather than one shift by
    /// `bitend - bitstart + 1`), exactly as Java does, so a full 64-bit field
    /// (`bitend - bitstart == 63`) shifts by 63 then 1 -- each individual shift amount stays
    /// in-range -- rather than attempting a single out-of-range shift by 64.
    fn field_max_value(bitstart: i32, bitend: i32) -> i64 {
        let mut res: i64 = -1;
        res <<= bitend - bitstart;
        res <<= 1;
        !res
    }

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

#[cfg(test)]
mod pattern_value_tests {
    use super::*;

    // Port of `ghidra.app.plugin.processors.sleigh.expression.PatternValue`'s contract
    // (`minValue()`/`maxValue()`), exercised here via `PatternExpression::min_value`/
    // `max_value` since this crate flattens the hierarchy into one enum.

    #[test]
    fn constant_min_and_max_are_the_stored_value() {
        // Java: `ConstantValue.minValue()`/`maxValue()` both just return `val`.
        let expr = PatternExpression::Constant(42);
        assert_eq!(expr.min_value().unwrap(), 42);
        assert_eq!(expr.max_value().unwrap(), 42);

        let negative = PatternExpression::Constant(-7);
        assert_eq!(negative.min_value().unwrap(), -7);
        assert_eq!(negative.max_value().unwrap(), -7);
    }

    #[test]
    fn token_field_min_is_zero_max_is_bit_mask() {
        // Java: `TokenField.minValue()` == 0; `maxValue()` == mask covering
        // (bitend - bitstart + 1) bits.
        let field = TokenField {
            bigendian: true,
            signbit: false,
            bitstart: 0,
            bitend: 7,
            bytestart: 0,
            byteend: 0,
            shift: 0,
        };
        let expr = PatternExpression::TokenField(field);
        assert_eq!(expr.min_value().unwrap(), 0);
        assert_eq!(expr.max_value().unwrap(), 0xff);
    }

    #[test]
    fn context_field_min_is_zero_max_is_bit_mask() {
        let field = ContextField {
            signbit: false,
            bitstart: 4,
            bitend: 11,
            bytestart: 0,
            byteend: 1,
            shift: 0,
        };
        let expr = PatternExpression::ContextField(field);
        assert_eq!(expr.min_value().unwrap(), 0);
        // 8-bit-wide field (bits 4..=11) -> mask 0xff.
        assert_eq!(expr.max_value().unwrap(), 0xff);
    }

    #[test]
    fn full_64_bit_token_field_max_value_is_negative_one() {
        // A field spanning the full 64 bits: `bitend - bitstart == 63`. Java computes this via
        // two shifts of 63 then 1 (rather than one shift of 64), each individually in-range;
        // starting from all-ones and shifting out every bit leaves 0, and `~0 == -1`. Ported
        // faithfully as two separate shifts in `field_max_value` for the same reason.
        let field = TokenField {
            bigendian: true,
            signbit: false,
            bitstart: 0,
            bitend: 63,
            bytestart: 0,
            byteend: 7,
            shift: 0,
        };
        let expr = PatternExpression::TokenField(field);
        assert_eq!(expr.max_value().unwrap(), -1);
    }

    #[test]
    fn start_end_next2_instruction_min_and_max_are_zero() {
        // Java: `StartInstructionValue`/`EndInstructionValue`/`Next2InstructionValue` all
        // return 0 for both minValue() and maxValue().
        for expr in [
            PatternExpression::StartInstruction,
            PatternExpression::EndInstruction,
            PatternExpression::Next2Instruction,
        ] {
            assert_eq!(expr.min_value().unwrap(), 0);
            assert_eq!(expr.max_value().unwrap(), 0);
        }
    }

    #[test]
    fn operand_value_min_and_max_both_error() {
        // Java: `OperandValue.minValue()`/`maxValue()` unconditionally throw
        // `new SleighException("Operand used in pattern expression")`. Faithfully reproduced as
        // an `Err` rather than silently returning a placeholder bound.
        let expr = PatternExpression::Operand(OperandValue {
            index: 0,
            constructor_id: 0,
        });
        let min_err = expr.min_value().unwrap_err();
        let max_err = expr.max_value().unwrap_err();
        assert_eq!(min_err.message(), "Operand used in pattern expression");
        assert_eq!(max_err.message(), "Operand used in pattern expression");
    }

    #[test]
    fn operator_variants_are_not_pattern_values() {
        // Java: `PlusExpression` (a `BinaryExpression`) and `NotExpression` (a
        // `UnaryExpression`) never extend `PatternValue`, so `minValue`/`maxValue` are not
        // callable on a reference statically typed as one of those classes. The flattened enum
        // can't express that at compile time, so it's enforced here at runtime instead.
        let plus = PatternExpression::Plus(
            Box::new(PatternExpression::Constant(1)),
            Box::new(PatternExpression::Constant(2)),
        );
        assert!(plus.min_value().is_err());
        assert!(plus.max_value().is_err());

        let not = PatternExpression::Not(Box::new(PatternExpression::Constant(1)));
        assert!(not.min_value().is_err());
        assert!(not.max_value().is_err());
    }
}
