//! A use-def node for a FLOAT2FLOAT p-code operation.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitFloatFloat2FloatOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
use crate::program::model::pcode::{OpCode, PcodeOp};

use super::{JitFloatUnOp, JitUnOp};

/// A use-def node for the [`OpCode::FloatFloat2Float`] p-code operation.
///
/// Port of the Java record `JitFloatFloat2FloatOp(PcodeOp op, JitOutVar out, JitVal u) implements
/// JitFloatUnOp`.
///
/// # Differences from Java
///
/// As with the binary op nodes (see
/// [`JitBinOp`](crate::pcode::emu::jit::op::jit_bin_op::JitBinOp)'s docs), Rust cannot express
/// `JitFloatUnOp`'s inherited defaults, so `link`/`unlink`/`inputs`/`type_for` are written out
/// directly here, mirroring `JitDefOp.link()` (`out().setDefinition(this)`) followed by
/// `JitUnOp.link()`'s `u().addUse(this, 0)` (and the symmetric `unlink()`).
#[derive(Clone)]
pub struct JitFloatFloat2FloatOp {
    op: PcodeOp,
    out: Arc<dyn JitOutVar>,
    u: Arc<dyn JitVal>,
}

impl JitFloatFloat2FloatOp {
    /// Port of the record constructor.
    pub fn new(op: PcodeOp, out: Arc<dyn JitOutVar>, u: Arc<dyn JitVal>) -> Self {
        Self { op, out, u }
    }

    /// Port of the record accessor `op()`.
    pub fn op(&self) -> &PcodeOp {
        &self.op
    }

    /// Port of the record accessor `out()`.
    pub fn out_ref(&self) -> &Arc<dyn JitOutVar> {
        &self.out
    }

    /// Port of the record accessor `u()`.
    pub fn u_ref(&self) -> &Arc<dyn JitVal> {
        &self.u
    }
}

impl JitOp for JitFloatFloat2FloatOp {
    /// Port of `JitUnOp.typeFor(int)`: position 0 is `uType()`, anything else throws
    /// `AssertionError`.
    fn type_for(&self, position: i32) -> JitTypeBehavior {
        match position {
            0 => JitTypeBehavior::Float,
            _ => panic!("AssertionError"),
        }
    }

    /// Port of `JitDefOp.link()` (`out().setDefinition(this)`) followed by `JitUnOp.link()`.
    fn link(&self) {
        self.out.set_definition(Some(self as &dyn JitDefOp));
        self.u.add_use(self, 0);
    }

    /// Port of `JitDefOp.unlink()` followed by `JitUnOp.unlink()`.
    fn unlink(&self) {
        let is_mine = self.out.definition().is_some_and(|def| {
            std::ptr::eq(Arc::as_ptr(&def) as *const (), self as *const Self as *const ())
        });
        if is_mine {
            self.out.set_definition(None);
        }
        self.u.remove_use(self, 0);
    }

    fn as_def_op(&self) -> Option<&dyn JitDefOp> {
        Some(self)
    }

    fn inputs(&self) -> Vec<Arc<dyn JitVal>> {
        vec![Arc::clone(&self.u)]
    }

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_un_op(self);
    }
}

impl JitDefOp for JitFloatFloat2FloatOp {
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
    }

    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }
}

impl JitUnOp for JitFloatFloat2FloatOp {
    fn u(&self) -> Arc<dyn JitVal> {
        Arc::clone(&self.u)
    }

    fn u_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }
}

impl JitFloatUnOp for JitFloatFloat2FloatOp {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitDefOp as JitDefOpTrait;
    use crate::pcode::emu::jit::var::JitVar;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;
    use std::sync::Mutex;

    fn make_op() -> PcodeOp {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0);
        let seqnum = SequenceNumber::new(addr, 0);
        PcodeOp::new(OpCode::FloatFloat2Float, seqnum, vec![], None)
    }

    struct MockOutVar;
    impl JitVal for MockOutVar {
        fn size(&self) -> i32 { 4 }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }
    impl JitVar for MockOutVar {
        fn id(&self) -> i32 { 0 }
        fn space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
        }
    }
    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            let addr = Address::new(space, 0);
            Varnode::new(addr, 4)
        }
    }
    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> { None }
    }

    struct MockVal;
    impl JitVal for MockVal {
        fn size(&self) -> i32 { 4 }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    /// Records the position of every `add_use`/`remove_use` call it receives.
    struct RecordingVal {
        added: Mutex<Vec<i32>>,
        removed: Mutex<Vec<i32>>,
    }
    impl RecordingVal {
        fn new() -> Self {
            Self { added: Mutex::new(Vec::new()), removed: Mutex::new(Vec::new()) }
        }
    }
    impl JitVal for RecordingVal {
        fn size(&self) -> i32 { 4 }
        fn add_use(&self, _op: &dyn JitOp, position: i32) {
            self.added.lock().unwrap().push(position);
        }
        fn remove_use(&self, _op: &dyn JitOp, position: i32) {
            self.removed.lock().unwrap().push(position);
        }
    }

    /// Records whether `set_definition` was called with `Some`/`None`.
    struct RecordingOutVar {
        set_some_count: Mutex<i32>,
        set_none_count: Mutex<i32>,
    }
    impl RecordingOutVar {
        fn new() -> Self {
            Self { set_some_count: Mutex::new(0), set_none_count: Mutex::new(0) }
        }
    }
    impl JitVal for RecordingOutVar {
        fn size(&self) -> i32 { 4 }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }
    impl JitVar for RecordingOutVar {
        fn id(&self) -> i32 { 0 }
        fn space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
        }
    }
    impl crate::pcode::emu::jit::var::JitVarnodeVar for RecordingOutVar {
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            let addr = Address::new(space, 0);
            Varnode::new(addr, 4)
        }
    }
    impl JitOutVar for RecordingOutVar {
        fn set_definition(&self, definition: Option<&dyn JitDefOp>) {
            if definition.is_some() {
                *self.set_some_count.lock().unwrap() += 1;
            } else {
                *self.set_none_count.lock().unwrap() += 1;
            }
        }
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> { None }
    }

    #[test]
    fn has_fields() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatFloat2FloatOp::new(make_op(), out, u);
        assert_eq!(op.op().opcode, OpCode::FloatFloat2Float);
    }

    #[test]
    fn implements_expected_traits() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatFloat2FloatOp::new(make_op(), out, u);
        let _: &dyn JitFloatUnOp = &op;
        let _: &dyn JitUnOp = &op;
        let _: &dyn JitDefOp = &op;
        let _: &dyn JitOp = &op;
    }

    #[test]
    fn type_for_dispatches_to_u_type() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatFloat2FloatOp::new(make_op(), out, u);
        assert_eq!(JitOp::type_for(&op, 0), JitUnOp::u_type(&op));
    }

    /// Java: `JitUnOp.typeFor`'s default `-> throw new AssertionError()` arm for any position
    /// other than 0.
    #[test]
    fn type_for_panics_on_invalid_position() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatFloat2FloatOp::new(make_op(), out, u);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| op.type_for(1)));
        assert!(result.is_err(), "type_for(1) should panic (Java: AssertionError)");
    }

    // Java: `JitDefOp.link()` (`out().setDefinition(this)`) followed by `JitUnOp.link()`
    // (`u().addUse(this, 0)`).
    #[test]
    fn link_sets_definition_and_adds_use() {
        let out = Arc::new(RecordingOutVar::new());
        let u = Arc::new(RecordingVal::new());
        let op = JitFloatFloat2FloatOp::new(
            make_op(),
            Arc::clone(&out) as Arc<dyn JitOutVar>,
            Arc::clone(&u) as Arc<dyn JitVal>,
        );

        op.link();

        assert_eq!(*out.set_some_count.lock().unwrap(), 1);
        assert_eq!(&*u.added.lock().unwrap(), &[0]);
    }

    // Java: `JitUnOp.unlink()` (`u().removeUse(this, 0)`), after `JitDefOp.unlink()`'s
    // identity-checked `setDefinition(null)`.
    #[test]
    fn unlink_removes_use() {
        let out = Arc::new(RecordingOutVar::new());
        let u = Arc::new(RecordingVal::new());
        let op = JitFloatFloat2FloatOp::new(
            make_op(),
            Arc::clone(&out) as Arc<dyn JitOutVar>,
            Arc::clone(&u) as Arc<dyn JitVal>,
        );

        op.unlink();

        assert_eq!(&*u.removed.lock().unwrap(), &[0]);
    }

    #[test]
    fn inputs_returns_u() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatFloat2FloatOp::new(make_op(), out, u);
        assert_eq!(JitOp::inputs(&op).len(), 1);
    }

    #[test]
    fn accept_dispatches_to_visit_un_op() {
        struct Probe(bool);
        impl crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor for Probe {
            fn visit_un_op(&mut self, _un_op: &dyn JitUnOp) {
                self.0 = true;
            }
        }
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatFloat2FloatOp::new(make_op(), out, u);
        let mut probe = Probe(false);
        op.accept(&mut probe);
        assert!(probe.0);
    }
}
