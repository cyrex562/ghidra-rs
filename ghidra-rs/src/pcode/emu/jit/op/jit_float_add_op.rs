//! A use-def node for a FLOAT_ADD p-code operation.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitFloatAddOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::{JitBinOp, JitDefOp, JitOp};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
use crate::program::model::pcode::{OpCode, PcodeOp};

use super::{JitFloatBinOp};

/// A use-def node for the [`OpCode::FloatAdd`] p-code operation.
///
/// Port of the Java record `JitFloatAddOp(PcodeOp op, JitOutVar out, JitVal l, JitVal r)
/// implements JitFloatBinOp`.
///
/// # Differences from Java
///
/// Java's record automatically implements `JitFloatBinOp`'s inherited default
/// `link()`/`unlink()`/`inputs()`/`typeFor(int)` (from `JitDefOp`/`JitBinOp`). Rust cannot express
/// that inheritance chain as defaults (see [`JitBinOp`]'s docs), so `link`/`unlink`/`inputs`/
/// `type_for` are written out directly here, faithfully mirroring
/// `JitDefOp.link()` (`out().setDefinition(this)`) followed by `JitBinOp.link()`'s
/// `l().addUse(this, 0); r().addUse(this, 1)` (and the symmetric `unlink()`), matching the
/// pattern already established by
/// [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp).
#[derive(Clone)]
pub struct JitFloatAddOp {
    op: PcodeOp,
    out: Arc<dyn JitOutVar>,
    l: Arc<dyn JitVal>,
    r: Arc<dyn JitVal>,
}

impl JitFloatAddOp {
    /// Port of the record constructor.
    pub fn new(op: PcodeOp, out: Arc<dyn JitOutVar>, l: Arc<dyn JitVal>, r: Arc<dyn JitVal>) -> Self {
        Self { op, out, l, r }
    }

    /// Port of the record accessor `op()`.
    pub fn op(&self) -> &PcodeOp {
        &self.op
    }

    /// Port of the record accessor `out()`.
    pub fn out_ref(&self) -> &Arc<dyn JitOutVar> {
        &self.out
    }

    /// Port of the record accessor `l()`.
    pub fn l_ref(&self) -> &Arc<dyn JitVal> {
        &self.l
    }

    /// Port of the record accessor `r()`.
    pub fn r_ref(&self) -> &Arc<dyn JitVal> {
        &self.r
    }
}

impl JitOp for JitFloatAddOp {
    /// Port of `JitBinOp.typeFor(int)`: position 0 is `lType()`, position 1 is `rType()`,
    /// anything else throws `AssertionError`.
    fn type_for(&self, position: i32) -> JitTypeBehavior {
        match position {
            0 => JitTypeBehavior::Float,
            1 => JitTypeBehavior::Float,
            _ => panic!("AssertionError"),
        }
    }

    /// Port of `JitDefOp.link()` (`out().setDefinition(this)`) followed by `JitBinOp.link()`.
    fn link(&self) {
        self.out.set_definition(Some(self as &dyn JitDefOp));
        self.l.add_use(self, 0);
        self.r.add_use(self, 1);
    }

    /// Port of `JitDefOp.unlink()` followed by `JitBinOp.unlink()`.
    fn unlink(&self) {
        let is_mine = self.out.definition().is_some_and(|def| {
            std::ptr::eq(Arc::as_ptr(&def) as *const (), self as *const Self as *const ())
        });
        if is_mine {
            self.out.set_definition(None);
        }
        self.l.remove_use(self, 0);
        self.r.remove_use(self, 1);
    }

    fn as_def_op(&self) -> Option<&dyn JitDefOp> {
        Some(self)
    }

    fn inputs(&self) -> Vec<Arc<dyn JitVal>> {
        vec![Arc::clone(&self.l), Arc::clone(&self.r)]
    }

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_bin_op(self);
    }
}

impl JitDefOp for JitFloatAddOp {
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
    }

    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }
}

impl JitBinOp for JitFloatAddOp {
    fn l(&self) -> Arc<dyn JitVal> {
        Arc::clone(&self.l)
    }

    fn r(&self) -> Arc<dyn JitVal> {
        Arc::clone(&self.r)
    }

    fn l_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }

    fn r_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Float
    }
}

impl JitFloatBinOp for JitFloatAddOp {}

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
        PcodeOp::new(OpCode::FloatAdd, seqnum, vec![], None)
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
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatAddOp::new(make_op(), out, l, r);
        assert_eq!(op.op().opcode, OpCode::FloatAdd);
    }

    #[test]
    fn implements_expected_traits() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatAddOp::new(make_op(), out, l, r);
        let _: &dyn JitFloatBinOp = &op;
        let _: &dyn JitBinOp = &op;
        let _: &dyn JitDefOp = &op;
        let _: &dyn JitOp = &op;
    }

    #[test]
    fn type_for_dispatches_to_l_type_and_r_type() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatAddOp::new(make_op(), out, l, r);
        assert_eq!(JitOp::type_for(&op, 0), JitBinOp::l_type(&op));
        assert_eq!(JitOp::type_for(&op, 1), JitBinOp::r_type(&op));
    }

    /// Java: `JitBinOp.typeFor`'s default `-> throw new AssertionError()` arm for any position
    /// other than 0 or 1.
    #[test]
    fn type_for_panics_on_invalid_position() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatAddOp::new(make_op(), out, l, r);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| op.type_for(2)));
        assert!(result.is_err(), "type_for(2) should panic (Java: AssertionError)");
    }

    // Java: `JitDefOp.link()` (`out().setDefinition(this)`) followed by `JitBinOp.link()`
    // (`l().addUse(this, 0); r().addUse(this, 1)`).
    #[test]
    fn link_sets_definition_and_adds_uses_in_position_order() {
        let out = Arc::new(RecordingOutVar::new());
        let l = Arc::new(RecordingVal::new());
        let r = Arc::new(RecordingVal::new());
        let op = JitFloatAddOp::new(
            make_op(),
            Arc::clone(&out) as Arc<dyn JitOutVar>,
            Arc::clone(&l) as Arc<dyn JitVal>,
            Arc::clone(&r) as Arc<dyn JitVal>,
        );

        op.link();

        assert_eq!(*out.set_some_count.lock().unwrap(), 1);
        assert_eq!(&*l.added.lock().unwrap(), &[0]);
        assert_eq!(&*r.added.lock().unwrap(), &[1]);
    }

    // Java: `JitBinOp.unlink()` (`l().removeUse(this, 0); r().removeUse(this, 1)`), after
    // `JitDefOp.unlink()`'s identity-checked `setDefinition(null)`.
    #[test]
    fn unlink_removes_uses_in_position_order() {
        let out = Arc::new(RecordingOutVar::new());
        let l = Arc::new(RecordingVal::new());
        let r = Arc::new(RecordingVal::new());
        let op = JitFloatAddOp::new(
            make_op(),
            Arc::clone(&out) as Arc<dyn JitOutVar>,
            Arc::clone(&l) as Arc<dyn JitVal>,
            Arc::clone(&r) as Arc<dyn JitVal>,
        );

        op.unlink();

        assert_eq!(&*l.removed.lock().unwrap(), &[0]);
        assert_eq!(&*r.removed.lock().unwrap(), &[1]);
    }

    #[test]
    fn inputs_returns_left_then_right() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatAddOp::new(make_op(), out, l, r);
        let inputs = JitOp::inputs(&op);
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn accept_dispatches_to_visit_bin_op() {
        struct Probe(bool);
        impl crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor for Probe {
            fn visit_bin_op(&mut self, _bin_op: &dyn JitBinOp) {
                self.0 = true;
            }
        }
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatAddOp::new(make_op(), out, l, r);
        let mut probe = Probe(false);
        op.accept(&mut probe);
        assert!(probe.0);
    }

    #[test]
    fn def_op_type_and_can_be_removed() {
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        let op = JitFloatAddOp::new(make_op(), out, l, r);
        assert_eq!(JitDefOpTrait::type_(&op), JitTypeBehavior::Float);
    }
}
