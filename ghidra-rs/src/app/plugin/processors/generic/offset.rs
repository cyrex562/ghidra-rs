//! Port of `ghidra.app.plugin.processors.generic.Offset`.

use std::collections::HashMap;

use crate::app::plugin::processors::generic::operand::{OperandId, OperandTable};
use crate::app::plugin::processors::generic::sled_exception::SledException;
use crate::program::model::mem::MemBuffer;

/// A byte offset into an instruction's bytes, optionally relative to the end of another operand.
///
/// Port of `ghidra.app.plugin.processors.generic.Offset`.
///
/// # Ownership
///
/// Java holds the operand this offset is relative to as a direct `Operand relTo` reference, found
/// by name in a `Hashtable<String, Operand>` during linking. Operands reference each other through
/// their offsets, so here they live in an [`OperandTable`] arena owned by their constructor and
/// `relTo` is an [`OperandId`]; the table is passed to [`Offset::get_offset`] at call time to
/// resolve it. Java's `Serializable` marker is not modeled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offset {
    /// The offset in bytes (Java stores the bit offset divided by eight).
    offset: i32,
    rel_to: Option<OperandId>,
    rel_to_name: String,
}

impl Offset {
    /// Java: `Offset(int off, String name) throws SledException`.
    ///
    /// `off` is in bits and must be a multiple of eight. An empty `name` means the offset is not
    /// relative to any operand.
    pub fn new(off: i32, name: &str) -> Result<Self, SledException> {
        if off % 8 != 0 {
            return Err(SledException::with_message(
                "offset must be a multiple of eight bits",
            ));
        }
        Ok(Offset {
            offset: off / 8,
            rel_to: None,
            rel_to_name: name.to_string(),
        })
    }

    /// Java: `Offset(int off, Operand rel)`: an offset relative to `rel`, which is already known
    /// (and named by `operands`) rather than looked up later by name.
    pub fn relative_to(
        off: i32,
        rel: OperandId,
        operands: &OperandTable,
    ) -> Result<Self, SledException> {
        let mut result = Self::new(off, operands.get(rel).name())?;
        result.rel_to = Some(rel);
        Ok(result)
    }

    /// The offset in bytes, not counting any relative operand's length.
    pub fn byte_offset(&self) -> i32 {
        self.offset
    }

    /// The operand this offset is relative to, once known.
    pub fn rel_to(&self) -> Option<OperandId> {
        self.rel_to
    }

    /// The name of the operand this offset is relative to; empty if it is not relative.
    pub fn rel_to_name(&self) -> &str {
        &self.rel_to_name
    }

    /// Java: `setRelativeOffset(Hashtable<String, Operand> opHash) throws SledException`.
    ///
    /// If this offset names an operand, resolve it through `op_hash`; it is an error for the name
    /// to be missing.
    pub fn set_relative_offset(
        &mut self,
        op_hash: &HashMap<String, OperandId>,
    ) -> Result<(), SledException> {
        if !self.rel_to_name.is_empty() {
            match op_hash.get(&self.rel_to_name) {
                Some(id) => self.rel_to = Some(*id),
                None => {
                    // Java assigns the (null) lookup result before throwing.
                    self.rel_to = None;
                    return Err(SledException::with_message(
                        "unable to find relative operand",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Java: `getOffset(MemBuffer buf, int off) throws Exception`.
    ///
    /// The offset into `buf` this object points to given the bytes there: `off` plus this byte
    /// offset, plus the length of the relative operand (evaluated at `off`) if there is one.
    pub fn get_offset(
        &self,
        operands: &OperandTable,
        buf: &dyn MemBuffer,
        off: i32,
    ) -> Result<i32, SledException> {
        let mut o = off.wrapping_add(self.offset);
        if let Some(rel) = self.rel_to {
            o = o.wrapping_add(operands.get(rel).length(operands, buf, off)?);
        }
        Ok(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::test_support::TestMemBuffer;

    #[test]
    fn bit_offset_must_be_byte_aligned() {
        let err = Offset::new(12, "").unwrap_err();
        assert_eq!(err.message(), "offset must be a multiple of eight bits");
        assert_eq!(Offset::new(16, "").unwrap().byte_offset(), 2);
        assert_eq!(Offset::new(-8, "").unwrap().byte_offset(), -1);
    }

    #[test]
    fn absolute_offset_adds_to_incoming_offset() {
        let table = OperandTable::new();
        let o = Offset::new(24, "").unwrap();
        let buf = TestMemBuffer { addr_offset: 0 };
        assert_eq!(o.get_offset(&table, &buf, 5).unwrap(), 8);
    }

    #[test]
    fn unnamed_offset_ignores_linking() {
        let mut o = Offset::new(8, "").unwrap();
        o.set_relative_offset(&HashMap::new()).unwrap();
        assert_eq!(o.rel_to(), None);
    }

    #[test]
    fn missing_relative_operand_is_an_error() {
        let mut o = Offset::new(8, "src").unwrap();
        let err = o.set_relative_offset(&HashMap::new()).unwrap_err();
        assert_eq!(err.message(), "unable to find relative operand");
    }
}
