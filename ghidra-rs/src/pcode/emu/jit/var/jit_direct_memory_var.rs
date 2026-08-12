//! A p-code variable node with a fixed location in memory.
//!
//! Port of `ghidra.pcode.emu.jit.var.JitDirectMemoryVar`.

use std::sync::Arc;

use crate::pcode::emu::jit::var::{JitVal, JitVar, JitVarnodeVar};
use crate::pcode::seam_stubs::{JitMemoryVar, JitOp};
use crate::program::model::address::AddressSpace;
use crate::program::model::pcode::Varnode;

/// A p-code variable node with a fixed location in memory.
///
/// This represents an input operand located in memory. Its value can be accessed directly from
/// the JIT executor state at run time.
#[derive(Debug, Clone)]
pub struct JitDirectMemoryVar {
    id: i32,
    varnode: Varnode,
}

impl JitDirectMemoryVar {
    /// Construct a variable.
    ///
    /// # Arguments
    ///
    /// * `id` - the unique id
    /// * `varnode` - the varnode
    pub fn new(id: i32, varnode: Varnode) -> Self {
        if varnode.get_size() < 1 {
            panic!("Varnode must have size at least 1");
        }
        Self { id, varnode }
    }
}

impl JitVal for JitDirectMemoryVar {
    fn size(&self) -> i32 {
        self.varnode.get_size()
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        // A plain method call on the concrete `Self`, not through `visitor`, since
        // `JitOpVisitor::visit_var` is `Self: Sized`-bounded and so isn't callable on the
        // `dyn JitOpVisitor` this method is given.
        JitVar::accept_var(self, visitor);
    }
}

impl JitVar for JitDirectMemoryVar {
    fn id(&self) -> i32 {
        self.id
    }

    fn space(&self) -> Arc<AddressSpace> {
        Arc::clone(self.varnode.get_address().space())
    }

    fn accept_var(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_direct_memory_var(self);
    }
}

impl JitVarnodeVar for JitDirectMemoryVar {
    fn varnode(&self) -> Varnode {
        self.varnode.clone()
    }
}

impl JitMemoryVar for JitDirectMemoryVar {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpaceType};

    #[test]
    fn test_new_valid() {
        let space = Arc::new(AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        ));
        let addr = Address::new(Arc::clone(&space), 0x1000);
        let varnode = Varnode::new(addr, 8);
        let var = JitDirectMemoryVar::new(42, varnode.clone());

        assert_eq!(var.id(), 42);
        assert_eq!(<JitDirectMemoryVar as JitVal>::size(&var), 8);
        assert_eq!(var.varnode().get_address().offset(), 0x1000);
    }

    #[test]
    #[should_panic(expected = "Varnode must have size at least 1")]
    fn test_new_invalid_size() {
        let space = Arc::new(AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        ));
        let addr = Address::new(Arc::clone(&space), 0x1000);
        let varnode = Varnode::new(addr, 0);
        JitDirectMemoryVar::new(42, varnode);
    }

    #[test]
    fn test_space() {
        let space = Arc::new(AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        ));
        let addr = Address::new(Arc::clone(&space), 0x2000);
        let varnode = Varnode::new(addr, 4);
        let var = JitDirectMemoryVar::new(1, varnode);

        assert_eq!(var.space().name(), "ram");
    }

    #[test]
    fn test_clone() {
        let space = Arc::new(AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        ));
        let addr = Address::new(Arc::clone(&space), 0x3000);
        let varnode = Varnode::new(addr, 8);
        let var = JitDirectMemoryVar::new(99, varnode);

        let var_clone = var.clone();
        assert_eq!(var_clone.id(), 99);
        assert_eq!(<JitDirectMemoryVar as JitVal>::size(&var_clone), 8);
        assert_eq!(var.id(), var_clone.id());
    }
}
