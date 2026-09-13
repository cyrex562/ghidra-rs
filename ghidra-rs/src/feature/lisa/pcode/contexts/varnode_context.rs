//! Port of `ghidra.lisa.pcode.contexts.VarnodeContext`.

use crate::program::model::pcode::Varnode;

/// Wraps a [`Varnode`] to expose the handful of properties the LiSA analysis framework needs
/// when reasoning about p-code operands, without exposing the full `Varnode` API.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.VarnodeContext` in the Java source.
#[derive(Clone, Debug)]
pub struct VarnodeContext {
    vn: Varnode,
}

impl VarnodeContext {
    /// Java: `VarnodeContext(Varnode vn)`.
    pub fn new(vn: Varnode) -> Self {
        Self { vn }
    }

    /// Returns the wrapped varnode.
    pub fn varnode(&self) -> &Varnode {
        &self.vn
    }

    /// Java: `isConstant()`.
    pub fn is_constant(&self) -> bool {
        self.vn.is_constant()
    }

    /// Java: `getSize()`.
    pub fn get_size(&self) -> i32 {
        self.vn.get_size()
    }

    /// Java: `getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.vn.get_offset()
    }

    /// Java: `getText()`.
    pub fn get_text(&self) -> String {
        self.vn.get_address().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn ram_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Varnode::new(Address::new(space, offset), size)
    }

    fn const_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0);
        Varnode::new(Address::new(space, offset), size)
    }

    #[test]
    fn wraps_a_ram_varnode_as_non_constant() {
        let ctx = VarnodeContext::new(ram_varnode(0x1000, 4));
        assert!(!ctx.is_constant());
        assert_eq!(ctx.get_size(), 4);
        assert_eq!(ctx.get_offset(), 0x1000);
    }

    #[test]
    fn wraps_a_constant_varnode() {
        let ctx = VarnodeContext::new(const_varnode(7, 8));
        assert!(ctx.is_constant());
        assert_eq!(ctx.get_offset(), 7);
        assert_eq!(ctx.get_size(), 8);
    }

    #[test]
    fn get_text_renders_the_varnode_address() {
        let vn = ram_varnode(0x2000, 4);
        let expected = vn.get_address().to_string();
        let ctx = VarnodeContext::new(vn);
        assert_eq!(ctx.get_text(), expected);
    }

    #[test]
    fn varnode_accessor_returns_the_wrapped_value() {
        let vn = ram_varnode(0x10, 1);
        let ctx = VarnodeContext::new(vn.clone());
        assert_eq!(ctx.varnode().get_offset(), vn.get_offset());
    }

    #[test]
    fn clone_is_independent() {
        let ctx = VarnodeContext::new(ram_varnode(0x10, 2));
        let cloned = ctx.clone();
        assert_eq!(ctx.get_offset(), cloned.get_offset());
    }
}
