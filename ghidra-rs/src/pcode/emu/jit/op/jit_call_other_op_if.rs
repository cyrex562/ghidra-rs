//! A use-def node for a `CALLOTHER` p-code op.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitCallOtherOpIf`.

use std::sync::Arc;

use crate::pcode::exec::pcode_userop_library::PcodeUseropDefinition;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::seam_stubs::{JitOp, JitTypeBehavior, MiniDFState};

/// A use-def node for a `PcodeOp::CALLOTHER`.
///
/// This requires [`Self::userop`] to exist. For the case of a missing userop, Java uses
/// `JitCallOtherMissingOp` (not yet ported).
///
/// # Differences from Java
///
/// Java's interface extends `JitOp` and provides *default* implementations of
/// `JitOp.canBeRemoved`/`inputs`/`typeFor`/`link`/`unlink` that its two implementors
/// (`JitCallOtherOp`, `JitCallOtherDefOp`) inherit automatically. Rust traits cannot override a
/// supertrait method under the same name, so those defaults are exposed here under distinct
/// `_call_other`-suffixed names -- the same convention
/// [`JitBoolBinOp`](crate::pcode::emu::jit::op::jit_bool_bin_op::JitBoolBinOp) already uses for
/// `JitBinOp.lType`/`rType`/`type`. A concrete implementor's own `JitOp` impl calls these helpers
/// explicitly, mirroring the Java implementors' explicit `JitCallOtherOpIf.super.link()` calls.
///
/// Java's `PcodeUseropDefinition<Object>` -- the type-erased userop domain used throughout the JIT
/// package -- is modeled as `PcodeUseropDefinition<()>`, since nothing in this interface inspects
/// the domain value.
pub trait JitCallOtherOpIf: JitOp {
    /// The userop definition.
    ///
    /// Port of `userop()`.
    fn userop(&self) -> Arc<dyn PcodeUseropDefinition<()>>;

    /// The arguments to the userop.
    ///
    /// Port of `args()`.
    fn args(&self) -> Vec<Box<dyn JitVal>>;

    /// The input operand use-def nodes, i.e. [`Self::args`].
    ///
    /// Port of the default `inputs()`.
    fn inputs_call_other(&self) -> Vec<Box<dyn JitVal>> {
        self.args()
    }

    /// The type behavior for each parameter in the userop definition.
    ///
    /// These should correspond to each argument (input).
    ///
    /// Port of `inputTypes()`.
    fn input_types(&self) -> Vec<JitTypeBehavior>;

    /// The required type behavior for the input at the given position in [`Self::args`].
    ///
    /// Port of the default `typeFor(int)`.
    fn type_for_call_other(&self, position: i32) -> JitTypeBehavior {
        self.input_types()[position as usize]
    }

    /// Get the captured data flow state at the call site.
    ///
    /// Port of `dfState()`.
    fn df_state(&self) -> MiniDFState;

    /// Indicates the operation can be removed if its output is never used.
    ///
    /// Port of the default `canBeRemoved()`.
    fn can_be_removed_call_other(&self) -> bool {
        !self.userop().has_side_effects()
    }

    /// Add this op to the [`JitVal`] uses of each argument.
    ///
    /// Port of the default `link()`.
    fn link_call_other(&self)
    where
        Self: Sized,
    {
        for (i, arg) in self.args().iter().enumerate() {
            arg.add_use(self, i as i32);
        }
    }

    /// Remove this op from the [`JitVal`] uses of each argument.
    ///
    /// Port of the default `unlink()`.
    fn unlink_call_other(&self)
    where
        Self: Sized,
    {
        for (i, arg) in self.args().iter().enumerate() {
            arg.remove_use(self, i as i32);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::pcode::exec::pcode_executor::PcodeExecutor;
    use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
    use crate::program::model::pcode::{PcodeOp, Varnode};

    struct MockUserop {
        side_effects: bool,
    }

    impl PcodeUseropDefinition<()> for MockUserop {
        fn get_name(&self) -> &str {
            "mock"
        }

        fn get_input_count(&self) -> i32 {
            1
        }

        fn execute(
            &self,
            _executor: &PcodeExecutor<()>,
            _library: &dyn PcodeUseropLibrary<()>,
            _op: &PcodeOp,
            _out_var: Option<&Varnode>,
            _in_vars: &[Varnode],
        ) {
        }

        fn is_functional(&self) -> bool {
            true
        }

        fn has_side_effects(&self) -> bool {
            self.side_effects
        }

        fn modifies_context(&self) -> bool {
            false
        }

        fn can_inline_pcode(&self) -> bool {
            false
        }

        fn get_output_type(&self) -> Option<std::any::TypeId> {
            None
        }

        fn get_java_method(&self) -> Option<()> {
            None
        }

        fn get_defining_library(
            &self,
        ) -> Option<&dyn crate::pcode::exec::pcode_userop_library::ErasedPcodeUseropLibrary> {
            None
        }
    }

    #[derive(Default)]
    struct MockVal {
        uses: Mutex<Vec<i32>>,
    }

    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            4
        }

        fn add_use(&self, _op: &dyn JitOp, position: i32) {
            self.uses.lock().unwrap().push(position);
        }

        fn remove_use(&self, _op: &dyn JitOp, position: i32) {
            self.uses.lock().unwrap().retain(|&p| p != position);
        }
    }

    struct TestCallOtherOp {
        userop: Arc<MockUserop>,
        args: Arc<MockVal>,
    }

    impl JitOp for TestCallOtherOp {
        fn type_for(&self, position: i32) -> JitTypeBehavior {
            self.type_for_call_other(position)
        }

        fn link(&self) {
            self.link_call_other();
        }

        fn unlink(&self) {
            self.unlink_call_other();
        }
    }

    impl JitCallOtherOpIf for TestCallOtherOp {
        fn userop(&self) -> Arc<dyn PcodeUseropDefinition<()>> {
            self.userop.clone()
        }

        fn args(&self) -> Vec<Box<dyn JitVal>> {
            // A single shared argument, boxed via a thin forwarding wrapper so `link`/`unlink`
            // observe the same `RefCell` regardless of how many `args()` calls occur.
            vec![Box::new(SharedVal(self.args.clone()))]
        }

        fn input_types(&self) -> Vec<JitTypeBehavior> {
            vec![JitTypeBehavior::Integer]
        }

        fn df_state(&self) -> MiniDFState {
            MiniDFState
        }
    }

    struct SharedVal(Arc<MockVal>);

    impl JitVal for SharedVal {
        fn size(&self) -> i32 {
            self.0.size()
        }

        fn add_use(&self, op: &dyn JitOp, position: i32) {
            self.0.add_use(op, position);
        }

        fn remove_use(&self, op: &dyn JitOp, position: i32) {
            self.0.remove_use(op, position);
        }
    }

    // Java: `JitCallOtherOpIf.canBeRemoved()` returns `!userop().hasSideEffects()`.
    #[test]
    fn can_be_removed_reflects_userop_side_effects() {
        let has_effects =
            TestCallOtherOp { userop: Arc::new(MockUserop { side_effects: true }), args: Default::default() };
        assert!(!has_effects.can_be_removed_call_other());

        let no_effects =
            TestCallOtherOp { userop: Arc::new(MockUserop { side_effects: false }), args: Default::default() };
        assert!(no_effects.can_be_removed_call_other());
    }

    // Java: `JitCallOtherOpIf.inputs()` returns `args()`, and `typeFor(position)` indexes
    // `inputTypes()`.
    #[test]
    fn inputs_and_type_for_delegate_to_args_and_input_types() {
        let op = TestCallOtherOp {
            userop: Arc::new(MockUserop { side_effects: false }),
            args: Default::default(),
        };
        assert_eq!(op.inputs_call_other().len(), op.args().len());
        assert_eq!(op.type_for_call_other(0), JitTypeBehavior::Integer);
    }

    // Java: `JitCallOtherOpIf.link()`/`unlink()` add/remove this op as a use of each argument at
    // its position.
    #[test]
    fn link_and_unlink_add_and_remove_uses_by_position() {
        let op = TestCallOtherOp {
            userop: Arc::new(MockUserop { side_effects: false }),
            args: Default::default(),
        };
        op.link_call_other();
        assert_eq!(&*op.args.uses.lock().unwrap(), &[0]);

        op.unlink_call_other();
        assert!(op.args.uses.lock().unwrap().is_empty());
    }
}
