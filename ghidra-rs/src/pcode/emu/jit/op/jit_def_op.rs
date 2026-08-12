//! A p-code operator use-def node with an output.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitDefOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::JitOp;
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::seam_stubs::{JitCatenateOp, JitSynthSubPieceOp, JitTypeBehavior};

/// A p-code operator use-def node with an output.
///
/// Port of the `ghidra.pcode.emu.jit.op.JitDefOp` interface: a use-def op that produces a
/// defined output value, extending the base [`JitOp`] with operations for managing that
/// definition relationship. Concrete implementations include [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp)
/// and the many def op types (currently unported).
pub trait JitDefOp: JitOp {
    /// The use-def variable node for the output.
    ///
    /// Port of `out()`.
    fn out(&self) -> Arc<dyn JitOutVar>;

    /// The required type behavior for the output.
    ///
    /// Port of `type()`. Defaults to `Integer` for most concrete def ops; only
    /// [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp) and similar synthetic ops
    /// override to [`JitTypeBehavior::Copy`].
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    /// Check whether this op can be removed if its output is unused.
    ///
    /// Port of `canBeRemoved()`: an op can be removed unless its output is written to a register
    /// or unique space (the former being caller-visible, the latter being used for analysis state).
    fn can_be_removed(&self) -> bool {
        use crate::program::model::address::AddressSpaceType;
        let space_type = self.out().varnode().get_address().space().space_type();
        space_type == AddressSpaceType::Unique || space_type == AddressSpaceType::Register
    }

    /// Stand-in for Java's `definition instanceof JitSynthSubPieceOp subsub` in
    /// `JitDataFlowArithmetic.trySimplifiedSubPiece`.
    ///
    /// `dyn JitDefOp` carries no downcast facility, so -- as
    /// [`JitVal::is_input_var`](crate::pcode::emu::jit::var::JitVal::is_input_var) already does for `instanceof JitInputVar` --
    /// the check is modeled as a defaulted query that only the matching type overrides.
    fn as_synth_sub_piece_op(&self) -> Option<&JitSynthSubPieceOp> {
        None
    }

    /// Stand-in for Java's `definition instanceof JitCatenateOp cat` in
    /// `JitDataFlowArithmetic.trySimplifiedSubPiece`. See [`Self::as_synth_sub_piece_op`].
    fn as_catenate_op(&self) -> Option<&JitCatenateOp> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::var::JitVal;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;
    use std::sync::Mutex;

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    struct MockOutVar {
        varnode: Varnode,
        definition: Mutex<Option<Arc<dyn JitDefOp>>>,
    }

    impl MockOutVar {
        fn new(varnode: Varnode) -> Self {
            Self {
                varnode,
                definition: Mutex::new(None),
            }
        }
    }

    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            self.varnode.get_size()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }


    impl crate::pcode::emu::jit::var::JitVar for MockOutVar {
        fn id(&self) -> i32 {
            0
        }
        fn space(&self) -> Arc<AddressSpace> {
            self.varnode.get_address().space().clone()
        }
    }

    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        // The varnode this mock was constructed with: `can_be_removed` reads its space, so the
        // whole point of each test is which space that is.
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            self.varnode.clone()
        }
    }

    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {
            // Can't store a &dyn as Arc, so this is a no-op in the test
        }

        fn set_definition_arc(&self, definition: Option<Arc<dyn JitDefOp>>) {
            *self.definition.lock().unwrap() = definition;
        }

        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            self.definition.lock().unwrap().clone()
        }
    }

    struct MockDefOp;

    impl JitOp for MockDefOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for MockDefOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unreachable!()
        }
    }

    #[test]
    fn can_be_removed_returns_true_for_unique_space() {
        let space = AddressSpace::new("unique", 64, 1, AddressSpaceType::Unique, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));

        struct TestDefOp(Arc<dyn JitOutVar>);
        impl JitOp for TestDefOp {
            fn type_for(&self, _position: i32) -> JitTypeBehavior {
                JitTypeBehavior::Integer
            }
            fn link(&self) {
                // Set the definition reference on the output variable
                self.out().set_definition(Some(self as &dyn JitDefOp));
            }
            fn unlink(&self) {
                // Unset the definition reference if still the definer
                if self.out().definition().is_some_and(|def| {
                    std::ptr::eq(
                        Arc::as_ptr(&def) as *const (),
                        self as *const Self as *const (),
                    )
                }) {
                    self.out().set_definition(None);
                }
            }
        }
        impl JitDefOp for TestDefOp {
            fn out(&self) -> Arc<dyn JitOutVar> {
                Arc::clone(&self.0)
            }
        }

        let op = TestDefOp(out);
        assert!(op.can_be_removed());
    }

    #[test]
    fn can_be_removed_returns_true_for_register_space() {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x0, 4)));

        struct TestDefOp(Arc<dyn JitOutVar>);
        impl JitOp for TestDefOp {
            fn type_for(&self, _position: i32) -> JitTypeBehavior {
                JitTypeBehavior::Integer
            }
            fn link(&self) {
                // Set the definition reference on the output variable
                self.out().set_definition(Some(self as &dyn JitDefOp));
            }
            fn unlink(&self) {
                // Unset the definition reference if still the definer
                if self.out().definition().is_some_and(|def| {
                    std::ptr::eq(
                        Arc::as_ptr(&def) as *const (),
                        self as *const Self as *const (),
                    )
                }) {
                    self.out().set_definition(None);
                }
            }
        }
        impl JitDefOp for TestDefOp {
            fn out(&self) -> Arc<dyn JitOutVar> {
                Arc::clone(&self.0)
            }
        }

        let op = TestDefOp(out);
        assert!(op.can_be_removed());
    }

    #[test]
    fn can_be_removed_returns_false_for_ram_space() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));

        struct TestDefOp(Arc<dyn JitOutVar>);
        impl JitOp for TestDefOp {
            fn type_for(&self, _position: i32) -> JitTypeBehavior {
                JitTypeBehavior::Integer
            }
            fn link(&self) {
                // Set the definition reference on the output variable
                self.out().set_definition(Some(self as &dyn JitDefOp));
            }
            fn unlink(&self) {
                // Unset the definition reference if still the definer
                if self.out().definition().is_some_and(|def| {
                    std::ptr::eq(
                        Arc::as_ptr(&def) as *const (),
                        self as *const Self as *const (),
                    )
                }) {
                    self.out().set_definition(None);
                }
            }
        }
        impl JitDefOp for TestDefOp {
            fn out(&self) -> Arc<dyn JitOutVar> {
                Arc::clone(&self.0)
            }
        }

        let op = TestDefOp(out);
        assert!(!op.can_be_removed());
    }

}
