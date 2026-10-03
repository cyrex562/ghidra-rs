//! Port of `ghidra.lisa.pcode.contexts.VarDefContext`.

use crate::feature::lisa::pcode::contexts::varnode_context::VarnodeContext;
use crate::program::model::pcode::{PcodeOp, Varnode};

/// A [`VarnodeContext`] paired with the [`PcodeOp`] that defines it.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.VarDefContext` in the Java source, which `extends
/// VarnodeContext`. Following this crate's composition-over-inheritance convention, this wraps a
/// `VarnodeContext` by composition instead, and re-exposes the members Java inherits unmodified
/// ([`VarDefContext::get_size`]/[`VarDefContext::get_offset`]/[`VarDefContext::varnode`]) alongside
/// the two Java overrides ([`VarDefContext::is_constant`]/[`VarDefContext::get_text`]).
#[derive(Clone, Debug)]
pub struct VarDefContext {
    base: VarnodeContext,
    op: PcodeOp,
}

impl VarDefContext {
    /// Java: `VarDefContext(PcodeOp op, Varnode vn)`.
    pub fn new(op: PcodeOp, vn: Varnode) -> Self {
        Self { base: VarnodeContext::new(vn), op }
    }

    /// Java: the overridden `isConstant()`, always `false` regardless of the wrapped varnode --
    /// a variable's *definition* is never itself a constant, even if the varnode happens to sit in
    /// the constant space (unusual, but not something this override special-cases).
    pub fn is_constant(&self) -> bool {
        false
    }

    /// Java: `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        &self.op
    }

    /// Java: the overridden `getText()`. Renders identically to the inherited
    /// [`VarnodeContext::get_text`] (both read `vn.getAddress().toString()`); Java's override is
    /// textually redundant with the base implementation, preserved here as its own method for
    /// parity with the Java source.
    pub fn get_text(&self) -> String {
        self.base.varnode().get_address().to_string()
    }

    /// Java: the inherited `getSize()`.
    pub fn get_size(&self) -> i32 {
        self.base.get_size()
    }

    /// Java: the inherited `getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.base.get_offset()
    }

    /// The wrapped varnode, standing in for direct access to `VarnodeContext`'s protected `vn`
    /// field.
    pub fn varnode(&self) -> &Varnode {
        self.base.varnode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, SequenceNumber};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0)
    }

    fn def_op() -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(OpCode::Copy, seq, vec![], None)
    }

    #[test]
    fn is_constant_is_always_false_even_for_a_constant_space_varnode() {
        let vn = Varnode::new(Address::new(const_space(), 7), 4);
        let ctx = VarDefContext::new(def_op(), vn);
        assert!(!ctx.is_constant());
    }

    #[test]
    fn get_op_returns_the_defining_op() {
        let op = def_op();
        let vn = Varnode::new(Address::new(ram_space(), 0x10), 4);
        let ctx = VarDefContext::new(op.clone(), vn);
        assert_eq!(ctx.get_op(), &op);
    }

    #[test]
    fn get_text_renders_the_varnodes_address() {
        let vn = Varnode::new(Address::new(ram_space(), 0x2000), 4);
        let expected = vn.get_address().to_string();
        let ctx = VarDefContext::new(def_op(), vn);
        assert_eq!(ctx.get_text(), expected);
    }

    #[test]
    fn size_and_offset_delegate_to_the_wrapped_varnode_context() {
        let vn = Varnode::new(Address::new(ram_space(), 0x30), 8);
        let ctx = VarDefContext::new(def_op(), vn);
        assert_eq!(ctx.get_size(), 8);
        assert_eq!(ctx.get_offset(), 0x30);
    }

    #[test]
    fn varnode_accessor_returns_the_wrapped_value() {
        let vn = Varnode::new(Address::new(ram_space(), 0x40), 2);
        let ctx = VarDefContext::new(def_op(), vn.clone());
        assert_eq!(ctx.varnode(), &vn);
    }
}
