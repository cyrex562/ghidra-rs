//! A p-code variable node with a fixed address.
//!
//! Port of `ghidra.pcode.emu.jit.var.JitVarnodeVar`.

use crate::pcode::emu::jit::op::JitOp;
use crate::pcode::emu::jit::var::JitVar;
use crate::program::model::pcode::Varnode;

/// A p-code variable node with a fixed address (given by a [`Varnode`]).
pub trait JitVarnodeVar: JitVar {
    /// The location of the variable.
    fn varnode(&self) -> Varnode;

    /// The size of the variable in bytes, derived from the varnode.
    fn size(&self) -> i32 {
        self.varnode().get_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::var::JitVal;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct TestVarnodeVar {
        varnode: Varnode,
        id: i32,
        space: Arc<AddressSpace>,
    }

    impl JitVal for TestVarnodeVar {
        fn size(&self) -> i32 {
            self.varnode.get_size()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    impl JitVar for TestVarnodeVar {
        fn id(&self) -> i32 {
            self.id
        }

        fn space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.space)
        }
    }

    impl JitVarnodeVar for TestVarnodeVar {
        fn varnode(&self) -> Varnode {
            self.varnode.clone()
        }
    }

    #[test]
    fn test_varnode_var_varnode() {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let addr = Address::new(Arc::clone(&space), 0x1000);
        let varnode = Varnode::new(addr, 8);
        let var = TestVarnodeVar {
            varnode: varnode.clone(),
            id: 1,
            space,
        };

        assert_eq!(var.varnode().get_address().offset(), 0x1000);
        assert_eq!(var.varnode().get_size(), 8);
    }

    #[test]
    fn test_varnode_var_size() {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let addr = Address::new(Arc::clone(&space), 0x2000);
        let varnode = Varnode::new(addr, 4);
        let var = TestVarnodeVar {
            varnode: varnode.clone(),
            id: 2,
            space,
        };

        assert_eq!(<TestVarnodeVar as JitVarnodeVar>::size(&var), 4);
    }

    #[test]
    fn test_varnode_var_id() {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let addr = Address::new(Arc::clone(&space), 0x3000);
        let varnode = Varnode::new(addr, 8);
        let var = TestVarnodeVar {
            varnode: varnode.clone(),
            id: 42,
            space: Arc::clone(&space),
        };

        assert_eq!(var.id(), 42);
    }
}
