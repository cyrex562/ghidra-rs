//! Port of `ghidra.app.plugin.processors.generic.BinaryExpression`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::app::plugin::processors::generic::constructor_info::ConstructorInfo;
use crate::app::plugin::processors::generic::expression_term::ExpressionTerm;
use crate::app::plugin::processors::generic::handle::Handle;
use crate::app::plugin::processors::generic::operand::{OperandId, OperandTable};
use crate::app::plugin::processors::generic::position::Position;
use crate::app::plugin::processors::generic::sled_exception::SledException;
use crate::program::model::address::AddressSpace;
use crate::program::model::mem::MemBuffer;
use crate::program::model::pcode::{PcodeOp, Varnode};

/// The arithmetic operation of a [`BinaryExpression`].
///
/// Java stores a raw `int opType` validated in the constructor against its `ADD`..`AND`
/// constants (`EQ` is declared but rejected). The validated value is this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// `l + r`
    Add,
    /// `l - r`
    Sub,
    /// `l * r`
    Mul,
    /// `l / r`
    Div,
    /// `l & r`
    And,
}

impl BinaryOp {
    /// Decode one of the [`BinaryExpression`] op-type constants, or `None` if Java's constructor
    /// would reject it.
    pub fn from_code(op: i32) -> Option<BinaryOp> {
        match op {
            BinaryExpression::ADD => Some(BinaryOp::Add),
            BinaryExpression::SUB => Some(BinaryOp::Sub),
            BinaryExpression::MUL => Some(BinaryOp::Mul),
            BinaryExpression::DIV => Some(BinaryOp::Div),
            BinaryExpression::AND => Some(BinaryOp::And),
            _ => None,
        }
    }

    /// The Java op-type constant for this operation.
    pub fn code(self) -> i32 {
        match self {
            BinaryOp::Add => BinaryExpression::ADD,
            BinaryOp::Sub => BinaryExpression::SUB,
            BinaryOp::Mul => BinaryExpression::MUL,
            BinaryOp::Div => BinaryExpression::DIV,
            BinaryOp::And => BinaryExpression::AND,
        }
    }
}

/// An arithmetic expression over two [`ExpressionTerm`]s, returning a pointer into an address
/// space.
///
/// Port of `ghidra.app.plugin.processors.generic.BinaryExpression`, a leaf class.
///
/// # Deviations from Java
///
/// * Java implements both `OperandValue` and `ExpressionValue`. Its terms' offsets may be
///   relative to other operands, which here live in an [`OperandTable`] arena and are referenced
///   by [`OperandId`] (see [`Offset`](super::offset::Offset)). Evaluating it therefore needs that
///   table, which neither trait's signature carries, so the same methods are inherent and take
///   `operands: &OperandTable`. [`Operand`](super::operand::Operand) and
///   [`ExpressionTerm`](super::expression_term::ExpressionTerm) hold it concretely (it is the only
///   `OperandValue` implementer in the Java source, and one of the closed set of
///   `ExpressionValue` kinds in [`ExpressionTermValue`](super::expression_term::ExpressionTermValue)).
/// * Java's `throws Exception` (spanning `SledException`, `MemoryAccessException` and the
///   `ArithmeticException` of a division by zero) is [`SledException`].
/// * `toString(MemBuffer, int)` is [`BinaryExpression::to_string_at`], matching
///   [`OperandValue::to_string_at`](super::OperandValue::to_string_at)'s naming.
/// * The two `getHandle` overloads are [`BinaryExpression::get_handle`] and
///   [`BinaryExpression::get_handle_with_pcode`], matching `OperandValue`'s naming.
pub struct BinaryExpression {
    /// Space ID of the address space into which this expression returns a pointer.
    space_id: i32,
    word_size: i32,
    constant_space: Arc<AddressSpace>,
    op_type: BinaryOp,
    left: ExpressionTerm,
    right: ExpressionTerm,
}

impl BinaryExpression {
    /// Java `INVALID_OP`.
    pub const INVALID_OP: i32 = -1;
    /// Java `ADD`.
    pub const ADD: i32 = 0;
    /// Java `SUB`.
    pub const SUB: i32 = 1;
    /// Java `MUL`.
    pub const MUL: i32 = 2;
    /// Java `DIV`.
    pub const DIV: i32 = 3;
    /// Java `EQ`: declared, but rejected by the constructor.
    pub const EQ: i32 = 4;
    /// Java `AND`.
    pub const AND: i32 = 5;

    /// Java: `BinaryExpression(int op, ExpressionTerm l, ExpressionTerm r, AddressSpace c)
    /// throws SledException`.
    ///
    /// The result points into `c` (whose word size is `c.getSize()/8`) until
    /// [`BinaryExpression::set_space`] says otherwise.
    pub fn new(
        op: i32,
        left: ExpressionTerm,
        right: ExpressionTerm,
        c: &Arc<AddressSpace>,
    ) -> Result<Self, SledException> {
        let op_type = BinaryOp::from_code(op).ok_or_else(|| {
            SledException::with_message(format!(
                "Unrecognized opType ({op}) in Binary Expression"
            ))
        })?;
        Ok(BinaryExpression {
            space_id: c.space_id(),
            word_size: c.size() / 8,
            constant_space: c.clone(),
            op_type,
            left,
            right,
        })
    }

    /// The operation.
    pub fn op_type(&self) -> BinaryOp {
        self.op_type
    }

    /// The left term.
    pub fn left(&self) -> &ExpressionTerm {
        &self.left
    }

    /// The right term.
    pub fn right(&self) -> &ExpressionTerm {
        &self.right
    }

    /// Java: `setSpace(AddressSpace space)`: the space this expression's result points into.
    pub fn set_space(&mut self, space: &AddressSpace) {
        self.space_id = space.space_id();
        self.word_size = space.size() / 8;
    }

    /// Java: `length(MemBuffer buf, int off)`: the longer of the two terms.
    pub fn length(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i32, SledException> {
        let left_len = self.left.length(operands, buf, off)?;
        let right_len = self.right.length(operands, buf, off)?;
        Ok(left_len.max(right_len))
    }

    /// Java: `getInfo(MemBuffer buf, int off)`: this expression's length, with no flow flags.
    pub fn get_info(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<ConstructorInfo, SledException> {
        Ok(ConstructorInfo::new(self.length(operands, buf, off)?, 0))
    }

    /// Java: `longValue(MemBuffer buf, int off)`.
    ///
    /// Arithmetic wraps, as Java `long` arithmetic does. Division by zero is an error (Java
    /// throws `ArithmeticException("/ by zero")`).
    pub fn long_value(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i64, SledException> {
        let l = self.left.long_value(operands, buf, off)?;
        let r = self.right.long_value(operands, buf, off)?;
        Ok(match self.op_type {
            BinaryOp::Add => l.wrapping_add(r),
            BinaryOp::Sub => l.wrapping_sub(r),
            BinaryOp::Mul => l.wrapping_mul(r),
            BinaryOp::Div => {
                if r == 0 {
                    return Err(SledException::with_message("/ by zero"));
                }
                l.wrapping_div(r)
            }
            BinaryOp::And => l & r,
        })
    }

    /// Java: `toString(MemBuffer buf, int off)`: the value as signed hex, `0x..` or `-0x..`.
    pub fn to_string_at(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<String, SledException> {
        let val = self.long_value(operands, buf, off)?;
        if val >= 0 {
            Ok(format!("0x{}", java_long_to_hex(val)))
        } else {
            Ok(format!("-0x{}", java_long_to_hex(val.wrapping_neg())))
        }
    }

    /// Java: `linkRelativeOffsets(Hashtable<String, Operand> opHash)`: links both terms.
    pub fn link_relative_offsets(
        &mut self,
        op_hash: &HashMap<String, OperandId>,
    ) -> Result<(), SledException> {
        self.left.link_relative_offsets(op_hash)?;
        self.right.link_relative_offsets(op_hash)
    }

    /// Java: `getHandle(Position position, int off)`: the value as a constant-space varnode of
    /// this expression's word size, tagged with its target space.
    pub fn get_handle(
        &self,
        operands: &OperandTable,
        position: &Position,
        off: i32,
    ) -> Result<Handle, SledException> {
        let val = self.long_value(operands, position.buffer(), off)?;
        let a = self.constant_space.checked_address(val)?;
        let v = Varnode::new(a, self.word_size);
        Ok(Handle::new(v, self.space_id, self.word_size))
    }

    /// Java: `getHandle(ArrayList<PcodeOp> pcode, Position position, int off)`. A binary
    /// expression never has any associated p-code, so `pcode` is left untouched.
    pub fn get_handle_with_pcode(
        &self,
        operands: &OperandTable,
        _pcode: &mut Vec<PcodeOp>,
        position: &Position,
        off: i32,
    ) -> Result<Handle, SledException> {
        self.get_handle(operands, position, off)
    }

    /// Java: `getAllHandles(ArrayList<Handle> handles, Position position, int off)`.
    pub fn get_all_handles(
        &self,
        operands: &OperandTable,
        handles: &mut Vec<Handle>,
        position: &Position,
        off: i32,
    ) -> Result<(), SledException> {
        handles.push(self.get_handle(operands, position, off)?);
        Ok(())
    }

    /// Java: `toList(ArrayList<Handle> list, Position position, int off)`.
    pub fn to_list(
        &self,
        operands: &OperandTable,
        list: &mut Vec<Handle>,
        position: &Position,
        off: i32,
    ) -> Result<(), SledException> {
        list.push(self.get_handle(operands, position, off)?);
        Ok(())
    }

    /// Java: `getSize()`: the word size in bits.
    pub fn get_size(&self) -> i32 {
        self.word_size * 8
    }
}

/// Java `Long.toString(v, 16)`: lowercase hex with a leading `-` for negative values (so
/// `Long.MIN_VALUE` renders as `-8000000000000000`).
fn java_long_to_hex(v: i64) -> String {
    if v < 0 {
        format!("-{:x}", (v as i128).unsigned_abs())
    } else {
        format!("{v:x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::constant::Constant;
    use crate::app::plugin::processors::generic::expression_term::ExpressionTermValue;
    use crate::app::plugin::processors::generic::offset::Offset;
    use crate::app::plugin::processors::generic::test_support::{
        const_space, make_position, ram_space, TestMemBuffer,
    };

    fn c(v: i64) -> ExpressionTerm {
        ExpressionTerm::new(
            ExpressionTermValue::Constant(Constant::new(v)),
            Offset::new(0, "").unwrap(),
        )
    }

    fn eval(op: i32, l: i64, r: i64) -> Result<i64, SledException> {
        let table = OperandTable::new();
        let buf = TestMemBuffer { addr_offset: 0 };
        BinaryExpression::new(op, c(l), c(r), &const_space())
            .unwrap()
            .long_value(&table, &buf, 0)
    }

    #[test]
    fn arithmetic_matches_java_long_semantics() {
        assert_eq!(eval(BinaryExpression::ADD, 3, 4).unwrap(), 7);
        assert_eq!(eval(BinaryExpression::SUB, 3, 8).unwrap(), -5);
        assert_eq!(eval(BinaryExpression::MUL, 6, 7).unwrap(), 42);
        assert_eq!(eval(BinaryExpression::DIV, -7, 2).unwrap(), -3);
        assert_eq!(eval(BinaryExpression::AND, 0xff0, 0x0ff).unwrap(), 0x0f0);
        assert_eq!(eval(BinaryExpression::ADD, i64::MAX, 1).unwrap(), i64::MIN);
        assert_eq!(eval(BinaryExpression::DIV, i64::MIN, -1).unwrap(), i64::MIN);
    }

    #[test]
    fn division_by_zero_is_an_error() {
        assert_eq!(eval(BinaryExpression::DIV, 1, 0).unwrap_err().message(), "/ by zero");
    }

    #[test]
    fn unrecognized_ops_are_rejected() {
        for op in [BinaryExpression::EQ, BinaryExpression::INVALID_OP, 17] {
            let err = BinaryExpression::new(op, c(1), c(2), &const_space()).err().unwrap();
            assert_eq!(
                err.message(),
                format!("Unrecognized opType ({op}) in Binary Expression")
            );
        }
        assert_eq!(BinaryOp::from_code(BinaryExpression::AND), Some(BinaryOp::And));
        assert_eq!(BinaryOp::Div.code(), 3);
    }

    #[test]
    fn to_string_renders_signed_hex() {
        let table = OperandTable::new();
        let buf = TestMemBuffer { addr_offset: 0 };
        let to_s = |op, l, r| {
            BinaryExpression::new(op, c(l), c(r), &const_space())
                .unwrap()
                .to_string_at(&table, &buf, 0)
                .unwrap()
        };
        assert_eq!(to_s(BinaryExpression::ADD, 0x10, 0x5), "0x15");
        assert_eq!(to_s(BinaryExpression::SUB, 0, 5), "-0x5");
        assert_eq!(to_s(BinaryExpression::ADD, 0, 0), "0x0");
        // Java: "-0x" + Long.toString(-Long.MIN_VALUE, 16)
        assert_eq!(to_s(BinaryExpression::SUB, i64::MIN, 0), "-0x-8000000000000000");
    }

    #[test]
    fn length_is_the_longer_term() {
        let table = OperandTable::new();
        let buf = TestMemBuffer { addr_offset: 0 };
        let long_term = ExpressionTerm::new(
            ExpressionTermValue::Constant(Constant::new(0)),
            Offset::new(32, "").unwrap(),
        );
        let bin = BinaryExpression::new(BinaryExpression::ADD, c(1), long_term, &const_space())
            .unwrap();
        assert_eq!(bin.length(&table, &buf, 0).unwrap(), 4);
        let info = bin.get_info(&table, &buf, 0).unwrap();
        assert_eq!(info.get_length(), 4);
        assert_eq!(info.get_flow_flags(), 0);
    }

    #[test]
    fn handle_is_constant_varnode_tagged_with_target_space() {
        let table = OperandTable::new();
        let position = make_position(0x1000, 4);
        let mut bin =
            BinaryExpression::new(BinaryExpression::ADD, c(0x20), c(0x4), &const_space()).unwrap();
        let h = bin.get_handle(&table, &position, 0).unwrap();
        assert_eq!(h.get_ptr().get_offset(), 0x24);
        assert_eq!(h.get_ptr().get_size(), 8);
        assert_eq!(h.get_space(), const_space().space_id() as i64);
        assert_eq!(bin.get_size(), 64);

        bin.set_space(&ram_space());
        let h = bin.get_handle(&table, &position, 0).unwrap();
        assert_eq!(h.get_space(), ram_space().space_id() as i64);
        assert_eq!(h.get_size(), 4);
        assert_eq!(h.get_ptr().get_size(), 4);
        assert!(h.get_ptr().is_constant());
        assert_eq!(bin.get_size(), 32);

        let mut pcode = Vec::new();
        let mut handles = Vec::new();
        assert_eq!(bin.get_handle_with_pcode(&table, &mut pcode, &position, 0).unwrap(), h);
        assert!(pcode.is_empty());
        bin.get_all_handles(&table, &mut handles, &position, 0).unwrap();
        bin.to_list(&table, &mut handles, &position, 0).unwrap();
        assert_eq!(handles, vec![h.clone(), h]);
    }
}
