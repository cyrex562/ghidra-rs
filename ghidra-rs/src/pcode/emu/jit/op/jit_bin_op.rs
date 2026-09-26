//! A binary p-code operator use-def node.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitBinOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::JitDefOp;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;

/// A p-code operator use-def node with two inputs and one output.
///
/// Port of the `ghidra.pcode.emu.jit.op.JitBinOp` interface: a [`JitDefOp`] with a left and a
/// right input operand. Concrete implementations reach this through one of the type-behavior
/// subtraits -- [`JitBoolBinOp`](crate::pcode::emu::jit::op::jit_bool_bin_op::JitBoolBinOp),
/// [`JitIntBinOp`](crate::pcode::emu::jit::op::jit_int_bin_op::JitIntBinOp), and
/// [`JitFloatBinOp`](crate::pcode::emu::jit::op::jit_float_bin_op::JitFloatBinOp) -- rather than
/// implementing this trait directly.
///
/// # Differences from Java
///
/// Java's `JitBinOp` supplies default `link()`/`unlink()`/`inputs()`/`typeFor(int)` bodies that
/// call `l()`/`r()`. As with
/// [`JitUnOp`](crate::pcode::emu::jit::op::jit_un_op::JitUnOp) (see
/// [`JitOp`](crate::pcode::emu::jit::op::jit_op::JitOp)'s module docs for why), those four methods
/// live on `JitOp` itself with no default body to override from a subtrait, so this trait cannot
/// reproduce them as defaults: a Rust trait can't override an already-abstract supertrait method.
/// Each concrete implementor instead writes its own `JitOp` impl that mirrors Java's default
/// bodies directly -- `link` calls `self.l().add_use(self, 0)` then `self.r().add_use(self, 1)`;
/// `unlink` the matching `remove_use`s; `inputs` returns `vec![self.l(), self.r()]`; `typeFor`
/// matches position `0`/`1` to `l_type()`/`r_type()` and panics (`AssertionError`) otherwise. See
/// this module's tests for that pattern worked out against a mock implementor.
pub trait JitBinOp: JitDefOp {
    /// The use-def node for the left input operand.
    ///
    /// Port of `l()`.
    fn l(&self) -> Arc<dyn JitVal>;

    /// The use-def node for the right input operand.
    ///
    /// Port of `r()`.
    fn r(&self) -> Arc<dyn JitVal>;

    /// The required type behavior for the left operand.
    ///
    /// Port of `lType()`.
    fn l_type(&self) -> JitTypeBehavior;

    /// The required type behavior for the right operand.
    ///
    /// Port of `rType()`.
    fn r_type(&self) -> JitTypeBehavior;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp as JitDefOpTrait, JitOp};
    use crate::pcode::emu::jit::var::JitOutVar;
    use std::sync::Mutex;

    /// Records the order and position of every `add_use`/`remove_use` call it receives, tagged
    /// with which operand (`"l"` or `"r"`) it was constructed for.
    struct RecordingVal {
        tag: &'static str,
        added: Arc<Mutex<Vec<(&'static str, i32)>>>,
        removed: Arc<Mutex<Vec<(&'static str, i32)>>>,
    }

    impl JitVal for RecordingVal {
        fn size(&self) -> i32 {
            4
        }
        fn add_use(&self, _op: &dyn JitOp, position: i32) {
            self.added.lock().unwrap().push((self.tag, position));
        }
        fn remove_use(&self, _op: &dyn JitOp, position: i32) {
            self.removed.lock().unwrap().push((self.tag, position));
        }
    }

    struct MockOutVar;
    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            4
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }
    impl crate::pcode::emu::jit::var::JitVar for MockOutVar {
        fn id(&self) -> i32 {
            0
        }
        fn space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            crate::program::model::address::AddressSpace::new(
                "test",
                64,
                1,
                crate::program::model::address::AddressSpaceType::Ram,
                0,
            )
        }
    }
    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            Varnode::new(Address::new(space, 0), 4)
        }
    }
    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
    }

    /// A concrete `JitBinOp` that hand-implements `JitOp`'s `link`/`unlink`/`inputs`/`type_for`
    /// the way Java's default methods do, since (per this module's docs) the trait itself cannot
    /// supply those defaults.
    struct TestBinOp {
        l: Arc<dyn JitVal>,
        r: Arc<dyn JitVal>,
    }

    impl JitOp for TestBinOp {
        fn type_for(&self, position: i32) -> JitTypeBehavior {
            match position {
                0 => JitBinOp::l_type(self),
                1 => JitBinOp::r_type(self),
                _ => panic!("AssertionError"),
            }
        }

        fn link(&self) {
            self.l().add_use(self, 0);
            self.r().add_use(self, 1);
        }

        fn unlink(&self) {
            self.l().remove_use(self, 0);
            self.r().remove_use(self, 1);
        }

        fn inputs(&self) -> Vec<Arc<dyn JitVal>> {
            vec![self.l(), self.r()]
        }
    }

    impl JitDefOpTrait for TestBinOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            Arc::new(MockOutVar)
        }
    }

    impl JitBinOp for TestBinOp {
        fn l(&self) -> Arc<dyn JitVal> {
            Arc::clone(&self.l)
        }

        fn r(&self) -> Arc<dyn JitVal> {
            Arc::clone(&self.r)
        }

        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }
    }

    // Java: `JitBinOp.link` default is `l().addUse(this, 0); r().addUse(this, 1);`.
    #[test]
    fn link_adds_uses_to_left_then_right_operand_in_position_order() {
        let added = Arc::new(Mutex::new(Vec::new()));
        let removed = Arc::new(Mutex::new(Vec::new()));
        let op = TestBinOp {
            l: Arc::new(RecordingVal { tag: "l", added: Arc::clone(&added), removed: Arc::clone(&removed) }),
            r: Arc::new(RecordingVal { tag: "r", added: Arc::clone(&added), removed: Arc::clone(&removed) }),
        };

        op.link();

        assert_eq!(&*added.lock().unwrap(), &[("l", 0), ("r", 1)]);
    }

    // Java: `JitBinOp.unlink` default is `l().removeUse(this, 0); r().removeUse(this, 1);`.
    #[test]
    fn unlink_removes_uses_from_left_then_right_operand_in_position_order() {
        let added = Arc::new(Mutex::new(Vec::new()));
        let removed = Arc::new(Mutex::new(Vec::new()));
        let op = TestBinOp {
            l: Arc::new(RecordingVal { tag: "l", added: Arc::clone(&added), removed: Arc::clone(&removed) }),
            r: Arc::new(RecordingVal { tag: "r", added: Arc::clone(&added), removed: Arc::clone(&removed) }),
        };

        op.unlink();

        assert_eq!(&*removed.lock().unwrap(), &[("l", 0), ("r", 1)]);
    }

    // Java: `JitBinOp.inputs` default is `List.of(l(), r())`.
    #[test]
    fn inputs_returns_left_then_right_operand() {
        let added = Arc::new(Mutex::new(Vec::new()));
        let removed = Arc::new(Mutex::new(Vec::new()));
        let op = TestBinOp {
            l: Arc::new(RecordingVal { tag: "l", added: Arc::clone(&added), removed: Arc::clone(&removed) }),
            r: Arc::new(RecordingVal { tag: "r", added: Arc::clone(&added), removed: Arc::clone(&removed) }),
        };

        let inputs = op.inputs();

        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].size(), op.l().size());
        assert_eq!(inputs[1].size(), op.r().size());
    }

    // Java: `JitBinOp.typeFor` default maps position 0 -> lType(), 1 -> rType().
    #[test]
    fn type_for_dispatches_to_l_type_and_r_type() {
        let op = TestBinOp {
            l: Arc::new(MockOutVar),
            r: Arc::new(MockOutVar),
        };

        assert_eq!(op.type_for(0), JitTypeBehavior::Integer);
        assert_eq!(op.type_for(1), JitTypeBehavior::Float);
    }

    // Java: `JitBinOp.typeFor` default's `default -> throw new AssertionError();` arm.
    #[test]
    #[should_panic(expected = "AssertionError")]
    fn type_for_panics_on_position_outside_zero_or_one() {
        let op = TestBinOp {
            l: Arc::new(MockOutVar),
            r: Arc::new(MockOutVar),
        };

        op.type_for(2);
    }
}
