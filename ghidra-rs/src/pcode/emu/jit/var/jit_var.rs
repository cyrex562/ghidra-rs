//! A p-code variable use-def node.
//!
//! Port of `ghidra.pcode.emu.jit.var.JitVar`.

use std::sync::Arc;

use crate::pcode::seam_stubs::JitVal;
use crate::program::model::address::AddressSpace;

/// A p-code variable use-def node.
///
/// This trait extends [`JitVal`] and represents a variable in the p-code use-def graph.
/// Each variable has a unique identifier and belongs to a specific address space.
pub trait JitVar: JitVal {
    /// A unique id for this variable.
    fn id(&self) -> i32;

    /// The address space of this variable.
    fn space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVar {
        id: i32,
        space: Arc<AddressSpace>,
    }

    impl JitVal for TestVar {
        fn size(&self) -> i32 {
            8
        }

        fn add_use(&self, _op: &dyn crate::pcode::seam_stubs::JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn crate::pcode::seam_stubs::JitOp, _position: i32) {}
    }

    impl JitVar for TestVar {
        fn id(&self) -> i32 {
            self.id
        }

        fn space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.space)
        }
    }

    #[test]
    fn test_var_id() {
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let var = TestVar { id: 42, space };
        assert_eq!(var.id(), 42);
    }

    #[test]
    fn test_var_space() {
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let var = TestVar { id: 1, space: Arc::clone(&space) };
        assert_eq!(var.space().name(), "ram");
        assert_eq!(var.id(), 1);
    }
}
