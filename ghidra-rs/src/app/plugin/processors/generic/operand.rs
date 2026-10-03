//! Port of `ghidra.app.plugin.processors.generic.Operand`, plus the [`OperandTable`] arena that
//! owns a constructor's operands.

use std::collections::HashMap;

use crate::app::plugin::processors::generic::binary_expression::BinaryExpression;
use crate::app::plugin::processors::generic::constructor_info::ConstructorInfo;
use crate::app::plugin::processors::generic::handle::Handle;
use crate::app::plugin::processors::generic::offset::Offset;
use crate::app::plugin::processors::generic::position::Position;
use crate::app::plugin::processors::generic::sled_exception::SledException;
use crate::program::model::mem::MemBuffer;
use crate::program::model::pcode::PcodeOp;

/// A typed index of an [`Operand`] in its [`OperandTable`].
///
/// Java refers to operands by object identity (as `Offset.relTo`, as `HashMap<Object, Handle>`
/// keys, from `ConstantTemplate` and `VarnodeTemplate`); an `OperandId` is that identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OperandId(u32);

impl OperandId {
    /// The ID of the operand at `index` in its table.
    pub fn from_index(index: usize) -> Self {
        OperandId(u32::try_from(index).expect("operand index exceeds u32"))
    }

    /// This operand's position in its table.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// The arena of a constructor's operands.
///
/// Java's operands reference one another through [`Offset`]s relative to another operand's end,
/// resolved by name from a `Hashtable<String, Operand>`. Here the constructor owns its operands in
/// this table, the name index is [`OperandTable::names`], a relative offset holds an
/// [`OperandId`], and evaluation takes the table as a call-time argument to resolve it.
///
/// Operands are only ever added, so IDs stay valid for the table's lifetime.
#[derive(Default)]
pub struct OperandTable {
    operands: Vec<Operand>,
    by_name: HashMap<String, OperandId>,
}

impl OperandTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an operand, indexing it by name (a later operand with the same name replaces the
    /// earlier one in the index, as a later `Hashtable.put` would).
    pub fn add(&mut self, operand: Operand) -> OperandId {
        let id = OperandId::from_index(self.operands.len());
        self.by_name.insert(operand.name.clone(), id);
        self.operands.push(operand);
        id
    }

    /// The operand with the given ID.
    ///
    /// # Panics
    ///
    /// If `id` did not come from this table.
    pub fn get(&self, id: OperandId) -> &Operand {
        &self.operands[id.index()]
    }

    /// The operand with the given ID, mutably. Panics like [`OperandTable::get`].
    pub fn get_mut(&mut self, id: OperandId) -> &mut Operand {
        &mut self.operands[id.index()]
    }

    /// The operand named `name`, if any.
    pub fn find(&self, name: &str) -> Option<OperandId> {
        self.by_name.get(name).copied()
    }

    /// The name index: Java's `Hashtable<String, Operand> opHash`.
    pub fn names(&self) -> &HashMap<String, OperandId> {
        &self.by_name
    }

    /// The number of operands.
    pub fn len(&self) -> usize {
        self.operands.len()
    }

    /// Whether the table has no operands.
    pub fn is_empty(&self) -> bool {
        self.operands.is_empty()
    }

    /// Every operand's ID, in insertion order.
    pub fn ids(&self) -> impl Iterator<Item = OperandId> + '_ {
        (0..self.operands.len()).map(OperandId::from_index)
    }

    /// Call Java's `Operand.linkRelativeOffsets(opHash)` on every operand, with this table's name
    /// index as `opHash`. Stops at the first failure.
    pub fn link_relative_offsets(&mut self) -> Result<(), SledException> {
        for operand in &mut self.operands {
            operand.link_relative_offsets(&self.by_name)?;
        }
        Ok(())
    }

    /// Java: `Operand.getHandle(ArrayList<PcodeOp> pcode, Position position, int off)`.
    ///
    /// Computes the operand's handle, collecting any p-code, and records it (and whether it is
    /// dynamic) on the operand for [`Operand::get_cached_handle`] and [`Operand::dynamic`]. This
    /// lives on the table because the evaluation reads other operands while the result is written
    /// to this one.
    pub fn get_handle_with_pcode(
        &mut self,
        id: OperandId,
        pcode: &mut Vec<PcodeOp>,
        position: &Position,
        off: i32,
    ) -> Result<Handle, SledException> {
        let handle = {
            let operand = self.get(id);
            let o = operand.offset.get_offset(self, position.buffer(), off)?;
            operand.op.get_handle_with_pcode(self, pcode, position, o)?
        };
        let operand = self.get_mut(id);
        operand.handle = Some(handle.clone());
        operand.test_dynamic();
        Ok(handle)
    }

    /// Java: `Operand.getPcode(Position position)`: the p-code produced while computing the
    /// operand's handle at offset 0 (which also records that handle).
    pub fn get_pcode(
        &mut self,
        id: OperandId,
        position: &Position,
    ) -> Result<Vec<PcodeOp>, SledException> {
        let mut pcode = Vec::new();
        self.get_handle_with_pcode(id, &mut pcode, position, 0)?;
        Ok(pcode)
    }
}

/// A named operand of a generic-processor constructor: an operand value at an [`Offset`].
///
/// Port of `ghidra.app.plugin.processors.generic.Operand`. Operands live in an [`OperandTable`];
/// evaluation takes that table because this operand's offset (or its value's terms) may be
/// relative to another operand. The mutating `getHandle(ArrayList<PcodeOp>, Position, int)` and
/// `getPcode(Position)` are [`OperandTable::get_handle_with_pcode`] and
/// [`OperandTable::get_pcode`].
///
/// Java types the value as the `OperandValue` interface, whose only implementer in the Java source
/// is [`BinaryExpression`]; it is held concretely here. Java's (commented-out) name-based
/// `equals`/`hashCode` is not modeled: operands are compared by identity, i.e. by [`OperandId`].
/// Java's `Serializable` marker is not modeled.
pub struct Operand {
    dynamic: bool,
    name: String,
    op: BinaryExpression,
    offset: Offset,
    handle: Option<Handle>,
}

impl Operand {
    /// Java: `Operand(String n, OperandValue o, Offset off)`.
    pub fn new(name: impl Into<String>, op: BinaryExpression, offset: Offset) -> Self {
        Operand {
            dynamic: false,
            name: name.into(),
            op,
            offset,
            handle: None,
        }
    }

    /// Java: `toString(MemBuffer buf, int off)`.
    pub fn to_string_at(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<String, SledException> {
        let o = self.offset.get_offset(operands, buf, off)?;
        self.op.to_string_at(operands, buf, o)
    }

    /// Java: `length(MemBuffer buf, int off)`: the distance from `off` to the operand's offset,
    /// plus the value's length there.
    pub fn length(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i32, SledException> {
        let o = self.offset.get_offset(operands, buf, off)?;
        Ok(self
            .op
            .length(operands, buf, o)?
            .wrapping_add(o)
            .wrapping_sub(off))
    }

    /// Java: `getInfo(MemBuffer buf, int off)`: the value's info, with its length extended by the
    /// distance from `off` to the operand's offset.
    pub fn get_info(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<ConstructorInfo, SledException> {
        let o = self.offset.get_offset(operands, buf, off)?;
        let mut opinfo = self.op.get_info(operands, buf, o)?;
        opinfo.add_length(o.wrapping_sub(off));
        Ok(opinfo)
    }

    /// Java: `name()`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The operand's value.
    pub fn value(&self) -> &BinaryExpression {
        &self.op
    }

    /// The operand's offset.
    pub fn offset(&self) -> &Offset {
        &self.offset
    }

    /// Java: `linkRelativeOffsets(Hashtable<String, Operand> opHash)`.
    ///
    /// Java links the value when it is a `BinaryExpression` and otherwise links the operand's own
    /// offset. `BinaryExpression` is the value's only possible kind, so this links the value's
    /// terms; the operand's own offset keeps whatever operand it was constructed relative to.
    pub fn link_relative_offsets(
        &mut self,
        op_hash: &HashMap<String, OperandId>,
    ) -> Result<(), SledException> {
        self.op.link_relative_offsets(op_hash)
    }

    /// Java: `getHandle()`: the handle recorded by the last
    /// [`OperandTable::get_handle_with_pcode`], if any.
    pub fn get_cached_handle(&self) -> Option<&Handle> {
        self.handle.as_ref()
    }

    /// Java: `getHandle(Position position, int off)`: a handle for this operand *without*
    /// generating any p-code or recording it.
    pub fn get_handle(
        &self,
        operands: &OperandTable,
        position: &Position,
        off: i32,
    ) -> Result<Handle, SledException> {
        let o = self.offset.get_offset(operands, position.buffer(), off)?;
        self.op.get_handle(operands, position, o)
    }

    /// Java: `getAllHandles(ArrayList<Handle> handles, Position position, int off)`.
    pub fn get_all_handles(
        &self,
        operands: &OperandTable,
        handles: &mut Vec<Handle>,
        position: &Position,
        off: i32,
    ) -> Result<(), SledException> {
        let o = self.offset.get_offset(operands, position.buffer(), off)?;
        self.op.get_all_handles(operands, handles, position, o)
    }

    /// Java: `dynamic()`: whether the recorded handle is dynamic (`false` before any handle is
    /// recorded).
    pub fn dynamic(&self) -> bool {
        self.dynamic
    }

    fn test_dynamic(&mut self) {
        // It's possible this param will never be used, so a missing handle is not dynamic.
        self.dynamic = self.handle.as_ref().is_some_and(Handle::dynamic);
    }

    /// Java: `toList(ArrayList<Handle> list, Position position, int off)`.
    pub fn to_list(
        &self,
        operands: &OperandTable,
        list: &mut Vec<Handle>,
        position: &Position,
        off: i32,
    ) -> Result<(), SledException> {
        let o = self.offset.get_offset(operands, position.buffer(), off)?;
        self.op.to_list(operands, list, position, o)
    }

    /// Java: `getSize()`: the value's size in bits.
    pub fn get_size(&self) -> i32 {
        self.op.get_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::constant::Constant;
    use crate::app::plugin::processors::generic::expression_term::{
        ExpressionTerm, ExpressionTermValue,
    };
    use crate::app::plugin::processors::generic::label::Label;
    use crate::app::plugin::processors::generic::test_support::{
        const_space, make_position, TestMemBuffer,
    };

    fn term(val: ExpressionTermValue, bit_off: i32, rel: &str) -> ExpressionTerm {
        ExpressionTerm::new(val, Offset::new(bit_off, rel).unwrap())
    }

    fn constant(v: i64) -> ExpressionTermValue {
        ExpressionTermValue::Constant(Constant::new(v))
    }

    /// `left + right` in the constant space.
    fn add(left: ExpressionTerm, right: ExpressionTerm) -> BinaryExpression {
        BinaryExpression::new(BinaryExpression::ADD, left, right, &const_space()).unwrap()
    }

    /// Operand `a`: a 2-byte-wide value (its right term sits 16 bits in) at offset 0.
    /// Operand `b`: `label + 1`, with the label term 8 bits past the end of `a`.
    fn two_operand_table() -> (OperandTable, OperandId, OperandId) {
        let mut table = OperandTable::new();
        let a = table.add(Operand::new(
            "a",
            add(term(constant(5), 0, ""), term(constant(0), 16, "")),
            Offset::new(0, "").unwrap(),
        ));
        let b = table.add(Operand::new(
            "b",
            add(
                term(ExpressionTermValue::Label(Label::new()), 8, "a"),
                term(constant(1), 0, ""),
            ),
            Offset::new(0, "").unwrap(),
        ));
        (table, a, b)
    }

    #[test]
    fn table_indexes_by_name() {
        let (table, a, b) = two_operand_table();
        assert_eq!(table.len(), 2);
        assert_eq!(table.find("a"), Some(a));
        assert_eq!(table.find("b"), Some(b));
        assert_eq!(table.find("c"), None);
        assert_eq!(table.ids().collect::<Vec<_>>(), vec![a, b]);
        assert_eq!(table.get(b).name(), "b");
    }

    #[test]
    fn length_counts_offset_and_value() {
        let (table, a, _) = two_operand_table();
        let buf = TestMemBuffer { addr_offset: 0x1000 };
        assert_eq!(table.get(a).length(&table, &buf, 0).unwrap(), 2);
        assert_eq!(table.get(a).length(&table, &buf, 10).unwrap(), 2);
        let info = table.get(a).get_info(&table, &buf, 0).unwrap();
        assert_eq!(info.get_length(), 2);
    }

    #[test]
    fn relative_terms_resolve_only_after_linking() {
        let (mut table, _, b) = two_operand_table();
        let buf = TestMemBuffer { addr_offset: 0x1000 };
        // Unlinked: the label term sits at 0 + 1 byte.
        assert_eq!(table.get(b).to_string_at(&table, &buf, 0).unwrap(), "0x1002");

        table.link_relative_offsets().unwrap();
        // Linked: 0 + 1 byte + length(a) == 3, so label == 0x1003, plus 1.
        assert_eq!(table.get(b).to_string_at(&table, &buf, 0).unwrap(), "0x1004");
        assert_eq!(table.get(b).length(&table, &buf, 0).unwrap(), 3);
    }

    #[test]
    fn linking_fails_on_unknown_operand_name() {
        let mut table = OperandTable::new();
        table.add(Operand::new(
            "x",
            add(term(constant(0), 0, "nope"), term(constant(0), 0, "")),
            Offset::new(0, "").unwrap(),
        ));
        let err = table.link_relative_offsets().unwrap_err();
        assert_eq!(err.message(), "unable to find relative operand");
    }

    #[test]
    fn operand_offset_relative_to_another_operand() {
        let (mut table, a, _) = two_operand_table();
        let offset = Offset::relative_to(8, a, &table).unwrap();
        assert_eq!(offset.rel_to_name(), "a");
        let c = table.add(Operand::new(
            "c",
            add(term(constant(7), 0, ""), term(constant(0), 0, "")),
            offset,
        ));
        let buf = TestMemBuffer { addr_offset: 0 };
        // offset = 0 + 1 + length(a)=2 == 3; the value itself has length 0.
        assert_eq!(table.get(c).length(&table, &buf, 0).unwrap(), 3);
        let info = table.get(c).get_info(&table, &buf, 0).unwrap();
        assert_eq!(info.get_length(), 3);
    }

    #[test]
    fn handles_are_recorded_only_by_the_pcode_variant() {
        let (mut table, a, _) = two_operand_table();
        let position = make_position(0x1000, 4);

        let plain = table.get(a).get_handle(&table, &position, 0).unwrap();
        assert_eq!(plain.get_ptr().get_offset(), 5);
        assert!(table.get(a).get_cached_handle().is_none());
        assert!(!table.get(a).dynamic());

        let mut pcode = Vec::new();
        let recorded = table.get_handle_with_pcode(a, &mut pcode, &position, 0).unwrap();
        assert_eq!(recorded, plain);
        assert!(pcode.is_empty());
        assert_eq!(table.get(a).get_cached_handle(), Some(&plain));
        // A constant varnode is not dynamic.
        assert!(!table.get(a).dynamic());

        assert!(table.get_pcode(a, &position).unwrap().is_empty());

        let mut handles = Vec::new();
        table.get(a).get_all_handles(&table, &mut handles, &position, 0).unwrap();
        table.get(a).to_list(&table, &mut handles, &position, 0).unwrap();
        assert_eq!(handles, vec![plain.clone(), plain]);
        assert_eq!(table.get(a).get_size(), 64);
    }
}
