//! Port of `ghidra.app.plugin.processors.generic.ConstantTemplate`.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::app::plugin::processors::generic::handle::Handle;
use crate::app::plugin::processors::generic::operand::{OperandId, OperandTable};
use crate::app::plugin::processors::generic::position::Position;
use crate::app::plugin::processors::generic::sled_exception::SledException;

/// A p-code template constant: a literal, a selected property of an operand's handle, or a
/// property of the instruction's position.
///
/// Port of `ghidra.app.plugin.processors.generic.ConstantTemplate`.
///
/// # Deviations from Java
///
/// * The operand is an [`OperandId`] into the constructor's [`OperandTable`], which resolution
///   takes as an argument (see [`Offset`](super::offset::Offset) for why).
/// * `type` stays a raw `i32` with the Java constants: [`ConstantTemplate::with_type`] accepts any
///   value and resolution returns `0` for an unknown one, exactly as Java does.
/// * A `HANDLE` template without an operand (only possible through `with_type(HANDLE)`), or one
///   whose operand is missing from the handle map, is an error where Java would throw a
///   `NullPointerException`.
/// * `equals`/`hashCode` are [`PartialEq`]/[`Hash`] with Java's semantics, including that two
///   `REAL` templates compare only their `(int)`-truncated values. Java hashes the operand by
///   identity; this hashes its [`OperandId`]. Java's `Serializable` marker is not modeled.
#[derive(Debug, Clone)]
pub struct ConstantTemplate {
    hash_code: i32,
    type_: i32,
    op: Option<OperandId>,
    real_value: i64,
    select1: i32,
    select2: i32,
}

impl ConstantTemplate {
    /// A literal value.
    pub const REAL: i32 = 1;
    /// A property of an operand's handle.
    pub const HANDLE: i32 = 2;
    /// The address of the start of the instruction.
    pub const JUMP_START: i32 = 3;
    /// The address of the next instruction.
    pub const JUMP_NEXT: i32 = 4;
    /// The space ID of the instruction's code space.
    pub const JUMP_CODESPACE: i32 = 5;

    /// Java: `ConstantTemplate(long val)`: a `REAL` literal.
    pub fn real(val: i64) -> Self {
        ConstantTemplate {
            hash_code: val as i32,
            type_: Self::REAL,
            op: None,
            real_value: val,
            select1: 0,
            select2: 0,
        }
    }

    /// Java: `ConstantTemplate(int t)`: a template of the given type with no value or operand.
    pub fn with_type(t: i32) -> Self {
        ConstantTemplate {
            hash_code: t,
            type_: t,
            op: None,
            real_value: 0,
            select1: 0,
            select2: 0,
        }
    }

    /// Java: `ConstantTemplate(Operand o, int sel1, int sel2)`: a `HANDLE` template reading
    /// `handle.getLong(sel1, sel2)` from `o`'s handle.
    pub fn handle(o: OperandId, sel1: i32, sel2: i32) -> Self {
        ConstantTemplate {
            hash_code: (o.index() as i32)
                .wrapping_add(sel1)
                .wrapping_add(10i32.wrapping_mul(sel2)),
            type_: Self::HANDLE,
            op: Some(o),
            real_value: 0,
            select1: sel1,
            select2: sel2,
        }
    }

    /// Java: `ConstantTemplate(Operand o, int sel1) throws SledException`: `handle(o, sel1, 0)`.
    ///
    /// Java then validates the type, which is always `HANDLE` here, so the check never fails; the
    /// `Result` is kept for signature parity.
    pub fn handle_with_select1(o: OperandId, sel1: i32) -> Result<Self, SledException> {
        let result = Self::handle(o, sel1, 0);
        match result.type_ {
            Self::REAL | Self::HANDLE | Self::JUMP_START | Self::JUMP_NEXT
            | Self::JUMP_CODESPACE => Ok(result),
            _ => Err(SledException::with_message(
                "invalid ConstantTemplate type encountered in resolve",
            )),
        }
    }

    /// Java: `type()`.
    pub fn type_(&self) -> i32 {
        self.type_
    }

    /// Java: `select1()`.
    pub fn select1(&self) -> i32 {
        self.select1
    }

    /// Java: `select2()`.
    pub fn select2(&self) -> i32 {
        self.select2
    }

    /// Java: `operand()`.
    pub fn operand(&self) -> Option<OperandId> {
        self.op
    }

    /// Java: `hashCode()`.
    pub fn hash_code(&self) -> i32 {
        self.hash_code
    }

    /// Java: `resolve(Position position, int off) throws Exception`.
    ///
    /// `HANDLE` computes the operand's handle (without p-code) at `off`; the `JUMP_*` types read
    /// the position; an unknown type resolves to `0`.
    pub fn resolve(
        &self,
        operands: &OperandTable,
        position: &Position,
        off: i32,
    ) -> Result<i64, SledException> {
        match self.type_ {
            Self::REAL => Ok(self.real_value),
            Self::HANDLE => {
                let op = self.require_operand()?;
                Ok(operands
                    .get(op)
                    .get_handle(operands, position, off)?
                    .get_long(self.select1, self.select2))
            }
            // The address of the beginning of this instruction.
            Self::JUMP_START => Ok(position.start_addr().offset()),
            Self::JUMP_NEXT => Ok(position.next_addr().offset()),
            Self::JUMP_CODESPACE => {
                Ok(position.buffer().get_address().space().space_id() as i64)
            }
            _ => Ok(0), // Should never reach here
        }
    }

    /// Java: `resolve(HashMap<Object, Handle> handles, Position position, int off)`.
    ///
    /// A `HANDLE` template reads its operand's entry in `handles`; anything else resolves as
    /// [`ConstantTemplate::resolve`].
    pub fn resolve_with_handles(
        &self,
        operands: &OperandTable,
        handles: &HashMap<OperandId, Handle>,
        position: &Position,
        off: i32,
    ) -> Result<i64, SledException> {
        if self.type_ == Self::HANDLE {
            let op = self.require_operand()?;
            let handle = handles.get(&op).ok_or_else(|| {
                SledException::with_message(format!(
                    "no handle for operand '{}'",
                    operands.get(op).name()
                ))
            })?;
            return Ok(handle.get_long(self.select1, self.select2));
        }
        self.resolve(operands, position, off)
    }

    fn require_operand(&self) -> Result<OperandId, SledException> {
        self.op.ok_or_else(|| {
            SledException::with_message("HANDLE ConstantTemplate has no operand")
        })
    }
}

impl PartialEq for ConstantTemplate {
    /// Java: `equals(Object)`.
    fn eq(&self, ct: &Self) -> bool {
        if ct.hash_code != self.hash_code || ct.type_ != self.type_ {
            return false;
        }
        if self.type_ == Self::HANDLE
            && (ct.op != self.op || ct.select1 != self.select1 || ct.select2 != self.select2)
        {
            return false;
        }
        true
    }
}

impl Eq for ConstantTemplate {}

impl Hash for ConstantTemplate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_code.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::binary_expression::BinaryExpression;
    use crate::app::plugin::processors::generic::constant::Constant;
    use crate::app::plugin::processors::generic::expression_term::{
        ExpressionTerm, ExpressionTermValue,
    };
    use crate::app::plugin::processors::generic::offset::Offset;
    use crate::app::plugin::processors::generic::operand::Operand;
    use crate::app::plugin::processors::generic::test_support::{
        const_space, make_position, ram_space,
    };
    use crate::program::model::address::Address;
    use crate::program::model::pcode::Varnode;

    fn table_with_constant_operand(v: i64) -> (OperandTable, OperandId) {
        let term = |v| {
            ExpressionTerm::new(
                ExpressionTermValue::Constant(Constant::new(v)),
                Offset::new(0, "").unwrap(),
            )
        };
        let mut table = OperandTable::new();
        let id = table.add(Operand::new(
            "imm",
            BinaryExpression::new(BinaryExpression::ADD, term(v), term(0), &const_space())
                .unwrap(),
            Offset::new(0, "").unwrap(),
        ));
        (table, id)
    }

    #[test]
    fn resolves_real_and_position_types() {
        let table = OperandTable::new();
        let position = make_position(0x4000, 6);
        assert_eq!(ConstantTemplate::real(-9).resolve(&table, &position, 0).unwrap(), -9);
        let start = ConstantTemplate::with_type(ConstantTemplate::JUMP_START);
        assert_eq!(start.resolve(&table, &position, 0).unwrap(), 0x4000);
        let next = ConstantTemplate::with_type(ConstantTemplate::JUMP_NEXT);
        assert_eq!(next.resolve(&table, &position, 0).unwrap(), 0x4006);
        let cs = ConstantTemplate::with_type(ConstantTemplate::JUMP_CODESPACE);
        assert_eq!(
            cs.resolve(&table, &position, 0).unwrap(),
            ram_space().space_id() as i64
        );
        assert_eq!(ConstantTemplate::with_type(99).resolve(&table, &position, 0).unwrap(), 0);
    }

    #[test]
    fn resolves_handle_selection_from_operand() {
        let (table, id) = table_with_constant_operand(0x1234);
        let position = make_position(0, 4);
        let off = ConstantTemplate::handle(id, Handle::OFFSET, Handle::OFFSET);
        assert_eq!(off.resolve(&table, &position, 0).unwrap(), 0x1234);
        let size = ConstantTemplate::handle_with_select1(id, Handle::SIZE).unwrap();
        assert_eq!(size.resolve(&table, &position, 0).unwrap(), 8);
        let missing = ConstantTemplate::with_type(ConstantTemplate::HANDLE);
        assert!(missing.resolve(&table, &position, 0).is_err());
    }

    #[test]
    fn handle_map_overrides_operand_evaluation() {
        let (table, id) = table_with_constant_operand(0x1234);
        let position = make_position(0, 4);
        let ct = ConstantTemplate::handle(id, Handle::OFFSET, Handle::OFFSET);
        let mut handles = HashMap::new();
        assert!(ct.resolve_with_handles(&table, &handles, &position, 0).is_err());
        let vn = Varnode::new(Address::new(const_space(), 0x77), 4);
        handles.insert(id, Handle::new(vn, 0, 4));
        assert_eq!(ct.resolve_with_handles(&table, &handles, &position, 0).unwrap(), 0x77);
        // Non-HANDLE types ignore the map.
        let real = ConstantTemplate::real(5);
        assert_eq!(real.resolve_with_handles(&table, &handles, &position, 0).unwrap(), 5);
    }

    #[test]
    fn equality_follows_java() {
        // REAL compares only the (int)-truncated hash and the type.
        assert_eq!(ConstantTemplate::real(1), ConstantTemplate::real(1 + (1 << 32)));
        assert_ne!(ConstantTemplate::real(1), ConstantTemplate::real(2));
        assert_ne!(
            ConstantTemplate::real(ConstantTemplate::JUMP_START as i64),
            ConstantTemplate::with_type(ConstantTemplate::JUMP_START)
        );
        let a = OperandId::from_index(0);
        let b = OperandId::from_index(1);
        assert_eq!(ConstantTemplate::handle(a, 1, 2), ConstantTemplate::handle(a, 1, 2));
        // Colliding hashes (0 + 1 == 1 + 0) but different operands.
        let x = ConstantTemplate::handle(a, 1, 0);
        let y = ConstantTemplate::handle(b, 0, 0);
        assert_eq!(x.hash_code(), y.hash_code());
        assert_ne!(x, y);
        assert_eq!(ConstantTemplate::handle(a, 2, 1).hash_code(), 12);
    }
}
