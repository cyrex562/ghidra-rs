//! A p-code variable node with a defining p-code op.
//!
//! Port of `ghidra.pcode.emu.jit.var.JitOutVar`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::JitDefOp;
use crate::pcode::emu::jit::var::JitVarnodeVar;

/// A p-code variable node with a defining p-code op.
///
/// This trait extends [`JitVarnodeVar`] and represents a variable in the p-code use-def graph
/// that has a defining operation.
pub trait JitOutVar: JitVarnodeVar {
    /// Set the defining p-code operator node.
    ///
    /// Port of `setDefinition(JitDefOp definition)`.
    fn set_definition(&self, definition: Option<&dyn JitDefOp>);

    /// The defining p-code operator node.
    ///
    /// This should "never" be null. The only exception is the short interim between constructing
    /// the node and setting its definition. Once this variable has been entered into the use-def
    /// graph, the definition should be non-null and final.
    ///
    /// Port of `definition(): JitDefOp`.
    fn definition(&self) -> Option<Arc<dyn JitDefOp>>;

    /// The retaining form of [`Self::set_definition`].
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
    /// which builds op nodes whose outputs must later report them back through
    /// [`Self::definition`]. Java does this wiring in `AbstractJitDefOp.link()`, as
    /// `out.setDefinition(this)`; `link(&self)` here cannot produce the `Arc<Self>` an out var
    /// has to keep, so the shared handle is passed in explicitly at the construction site (see
    /// [`JitDataFlowModel::notify_def_op`]). Defaults to a no-op so existing `impl JitOutVar`
    /// blocks -- which model no definition storage at all -- keep compiling.
    fn set_definition_arc(&self, definition: Option<Arc<dyn JitDefOp>>) {
        let _ = definition;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitOp;
    use crate::pcode::emu::jit::var::{JitVal, JitVar};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;
    use std::sync::Arc;

    struct TestOutVar {
        varnode: Varnode,
        id: i32,
        space: Arc<AddressSpace>,
        definition: Arc<std::sync::Mutex<Option<Arc<dyn JitDefOp>>>>,
    }

    impl JitVal for TestOutVar {
        fn size(&self) -> i32 {
            self.varnode.get_size()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    impl JitVar for TestOutVar {
        fn id(&self) -> i32 {
            self.id
        }

        fn space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.space)
        }
    }

    impl JitVarnodeVar for TestOutVar {
        fn varnode(&self) -> Varnode {
            self.varnode.clone()
        }
    }

    impl JitOutVar for TestOutVar {
        fn set_definition(&self, definition: Option<&dyn JitDefOp>) {
            let arc_def = definition.map(|d| {
                // We can't directly convert &dyn JitDefOp to Arc<dyn JitDefOp>
                // This is a test-only limitation; the real implementations
                // will store their Arc<dyn JitDefOp> directly
                panic!("Test helper: real implementations should store Arc directly");
            });
            *self.definition.lock().unwrap() = arc_def;
        }

        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            self.definition.lock().unwrap().clone()
        }
    }

    #[test]
    fn test_out_var_varnode() {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let addr = Address::new(Arc::clone(&space), 0x1000);
        let varnode = Varnode::new(addr, 8);
        let var = TestOutVar {
            varnode: varnode.clone(),
            id: 1,
            space,
            definition: Arc::new(std::sync::Mutex::new(None)),
        };

        assert_eq!(var.varnode().get_address().offset(), 0x1000);
        assert_eq!(var.varnode().get_size(), 8);
    }

    #[test]
    fn test_out_var_size() {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let addr = Address::new(Arc::clone(&space), 0x2000);
        let varnode = Varnode::new(addr, 4);
        let var = TestOutVar {
            varnode: varnode.clone(),
            id: 2,
            space,
            definition: Arc::new(std::sync::Mutex::new(None)),
        };

        assert_eq!(<TestOutVar as JitVarnodeVar>::size(&var), 4);
    }

    #[test]
    fn test_out_var_definition_none_initially() {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let addr = Address::new(Arc::clone(&space), 0x3000);
        let varnode = Varnode::new(addr, 8);
        let var = TestOutVar {
            varnode: varnode.clone(),
            id: 3,
            space,
            definition: Arc::new(std::sync::Mutex::new(None)),
        };

        assert!(var.definition().is_none());
    }
}
