//! Port of `ghidra.app.plugin.processors.generic.ExpressionTerm`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::app::plugin::processors::generic::binary_expression::BinaryExpression;
use crate::app::plugin::processors::generic::constant::Constant;
use crate::app::plugin::processors::generic::expression_value::ExpressionValue;
use crate::app::plugin::processors::generic::label::Label;
use crate::app::plugin::processors::generic::offset::Offset;
use crate::app::plugin::processors::generic::operand::{OperandId, OperandTable};
use crate::app::plugin::processors::generic::sled_exception::SledException;
use crate::program::model::address::AddressSpace;
use crate::program::model::mem::MemBuffer;

/// The value half of an [`ExpressionTerm`]: one of the package's
/// [`ExpressionValue`] implementations.
///
/// Java types this field as the `ExpressionValue` interface and tests
/// `val.getClass() == BinaryExpression.class` to special-case binary expressions. The in-package
/// implementers are exactly [`Constant`], [`Label`] and [`BinaryExpression`], so the field is this
/// closed enum and the class test is a `match`. A binary expression is the one kind whose
/// evaluation needs the owning [`OperandTable`] (its terms may be relative to other operands),
/// which is why it cannot simply be a `Box<dyn ExpressionValue>`.
pub enum ExpressionTermValue {
    /// A literal value.
    Constant(Constant),
    /// The address of the instruction bytes at the term's offset.
    Label(Label),
    /// An arithmetic combination of two further terms.
    Binary(Box<BinaryExpression>),
}

impl ExpressionTermValue {
    /// `ExpressionValue.longValue(MemBuffer, int)` for whichever kind this is.
    pub fn long_value(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i64, SledException> {
        match self {
            ExpressionTermValue::Constant(c) => Ok(c.long_value(buf, off)?),
            ExpressionTermValue::Label(l) => Ok(l.long_value(buf, off)?),
            ExpressionTermValue::Binary(b) => b.long_value(operands, buf, off),
        }
    }

    /// `ExpressionValue.length(MemBuffer, int)` for whichever kind this is.
    pub fn length(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i32, SledException> {
        match self {
            ExpressionTermValue::Constant(c) => Ok(ExpressionValue::length(c, buf, off)?),
            ExpressionTermValue::Label(l) => Ok(ExpressionValue::length(l, buf, off)?),
            ExpressionTermValue::Binary(b) => b.length(operands, buf, off),
        }
    }
}

/// An expression value evaluated at an [`Offset`] into the instruction bytes.
///
/// Port of `ghidra.app.plugin.processors.generic.ExpressionTerm`. Evaluation takes the owning
/// [`OperandTable`] because the offset (or a nested binary expression's offsets) may be relative
/// to another operand; see [`Offset`]'s docs. Java's `Serializable` marker is not modeled.
pub struct ExpressionTerm {
    val: ExpressionTermValue,
    offset: Offset,
}

impl ExpressionTerm {
    /// Java: `ExpressionTerm(ExpressionValue v, Offset off)`.
    pub fn new(val: ExpressionTermValue, offset: Offset) -> Self {
        ExpressionTerm { val, offset }
    }

    /// Java: `longValue(MemBuffer buf, int off) throws Exception`: the value, evaluated at this
    /// term's offset from `off`.
    pub fn long_value(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i64, SledException> {
        let o = self.offset.get_offset(operands, buf, off)?;
        self.val.long_value(operands, buf, o)
    }

    /// Java: `length(MemBuffer buf, int off) throws Exception`: the distance from `off` to the
    /// term's offset, plus the value's own length there.
    pub fn length(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i32, SledException> {
        let o = self.offset.get_offset(operands, buf, off)?;
        Ok(o.wrapping_sub(off)
            .wrapping_add(self.val.length(operands, buf, o)?))
    }

    /// Java: `linkRelativeOffsets(Hashtable<String, Operand> opHash)`.
    ///
    /// A binary expression links its own terms (and, exactly as in Java, this term's offset is
    /// then left unlinked); any other value links this term's offset.
    pub fn link_relative_offsets(
        &mut self,
        op_hash: &HashMap<String, OperandId>,
    ) -> Result<(), SledException> {
        match &mut self.val {
            ExpressionTermValue::Binary(b) => b.link_relative_offsets(op_hash),
            _ => self.offset.set_relative_offset(op_hash),
        }
    }

    /// Java: `getValue()`.
    pub fn get_value(&self) -> &ExpressionTermValue {
        &self.val
    }

    /// This term's offset.
    pub fn offset(&self) -> &Offset {
        &self.offset
    }

    /// Java: `setSpace(AddressSpace space) throws SledException`: sets the address space of the
    /// expression value, which must be a binary expression.
    pub fn set_space(&mut self, space: &Arc<AddressSpace>) -> Result<(), SledException> {
        match &mut self.val {
            ExpressionTermValue::Binary(b) => {
                b.set_space(space);
                Ok(())
            }
            _ => Err(SledException::with_message(
                "Can't add space to an ExpressionTerm that does not contain a BinaryExpression",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::test_support::{const_space, ram_space, TestMemBuffer};

    fn constant_term(v: i64, bit_off: i32) -> ExpressionTerm {
        ExpressionTerm::new(
            ExpressionTermValue::Constant(Constant::new(v)),
            Offset::new(bit_off, "").unwrap(),
        )
    }

    #[test]
    fn constant_ignores_offset_for_value_but_counts_it_in_length() {
        let table = OperandTable::new();
        let buf = TestMemBuffer { addr_offset: 0x1000 };
        let term = constant_term(42, 16);
        assert_eq!(term.long_value(&table, &buf, 3).unwrap(), 42);
        // (3 + 2) - 3 + Constant.length == 2
        assert_eq!(term.length(&table, &buf, 3).unwrap(), 2);
    }

    #[test]
    fn label_evaluates_to_buffer_address_plus_term_offset() {
        let table = OperandTable::new();
        let buf = TestMemBuffer { addr_offset: 0x1000 };
        let term = ExpressionTerm::new(
            ExpressionTermValue::Label(Label::new()),
            Offset::new(8, "").unwrap(),
        );
        assert_eq!(term.long_value(&table, &buf, 2).unwrap(), 0x1003);
    }

    #[test]
    fn set_space_requires_binary_expression() {
        let err = constant_term(1, 0).set_space(&ram_space()).unwrap_err();
        assert_eq!(
            err.message(),
            "Can't add space to an ExpressionTerm that does not contain a BinaryExpression"
        );

        let bin = BinaryExpression::new(
            BinaryExpression::ADD,
            constant_term(1, 0),
            constant_term(2, 0),
            &const_space(),
        )
        .unwrap();
        let mut term = ExpressionTerm::new(
            ExpressionTermValue::Binary(Box::new(bin)),
            Offset::new(0, "").unwrap(),
        );
        term.set_space(&ram_space()).unwrap();
        match term.get_value() {
            ExpressionTermValue::Binary(b) => assert_eq!(b.get_size(), 32),
            _ => unreachable!(),
        }
    }

    #[test]
    fn linking_a_binary_term_links_its_children_not_its_own_offset() {
        let child = ExpressionTerm::new(
            ExpressionTermValue::Constant(Constant::new(1)),
            Offset::new(0, "missing").unwrap(),
        );
        let bin = BinaryExpression::new(
            BinaryExpression::ADD,
            child,
            constant_term(2, 0),
            &const_space(),
        )
        .unwrap();
        // The term's own offset names an operand that does not exist, but Java never links it.
        let mut term = ExpressionTerm::new(
            ExpressionTermValue::Binary(Box::new(bin)),
            Offset::new(0, "also-missing").unwrap(),
        );
        let err = term.link_relative_offsets(&HashMap::new()).unwrap_err();
        assert_eq!(err.message(), "unable to find relative operand");

        let mut names = HashMap::new();
        names.insert("missing".to_string(), OperandId::from_index(0));
        term.link_relative_offsets(&names).unwrap();
        assert_eq!(term.offset().rel_to(), None);
    }
}
