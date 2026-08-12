//! The synthetic use-def node for phi nodes.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitPhiOp`.

use std::sync::{Arc, Mutex};

use crate::pcode::emu::jit::op::JitSyntheticOp;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::seam_stubs::{
    BlockFlow, JitBlock, JitDefOp, JitInputVar, JitOp, JitOutVar, JitTypeBehavior,
};

/// The synthetic use-def node for phi nodes.
///
/// Java models this as a `record JitPhiOp(JitBlock block, JitOutVar out, BidiMap<BlockFlow,
/// JitVal> options)`. The `BidiMap` (from Apache Commons Collections) is used here only for its
/// forward direction -- nothing in this type performs a value-to-key lookup -- so it is modeled as
/// an ordered `Vec` of pairs rather than pulling in a bidirectional-map dependency.
pub struct JitPhiOp {
    block: JitBlock,
    out: Arc<dyn JitOutVar>,
    options: Mutex<Vec<(BlockFlow, Arc<dyn JitVal>)>>,
}

impl JitPhiOp {
    /// Construct a phi node without any options, yet.
    ///
    /// Port of the compact constructor `JitPhiOp(JitBlock, JitOutVar)`.
    pub fn new(block: JitBlock, out: Arc<dyn JitOutVar>) -> Self {
        Self::with_options(block, out, Vec::new())
    }

    /// Construct a phi node with the given initial options.
    ///
    /// Port of the canonical (record) constructor `JitPhiOp(JitBlock, JitOutVar, BidiMap)`.
    pub fn with_options(
        block: JitBlock,
        out: Arc<dyn JitOutVar>,
        options: Vec<(BlockFlow, Arc<dyn JitVal>)>,
    ) -> Self {
        Self { block, out, options: Mutex::new(options) }
    }

    /// The block containing the op that generated this phi node.
    ///
    /// Port of the record accessor `block()`.
    pub fn block(&self) -> JitBlock {
        self.block
    }

    /// Add an option assuming the given flow is taken.
    ///
    /// Port of `addOption(BlockFlow, JitVal)`.
    ///
    /// # Differences from Java
    ///
    /// Java inserts into `options` before calling `option.addUse(this, 0)`; here the use is
    /// registered first since `option` is moved into storage afterward. The two calls are
    /// independent, so the order has no observable effect.
    pub fn add_option(&self, flow: BlockFlow, option: Arc<dyn JitVal>) {
        option.add_use(self, 0); // HACK: 0 is as good as any position
        self.options.lock().unwrap().push((flow, option));
    }

    /// Check if one of the options is an input to the passage.
    ///
    /// Port of `hasInputOption()`.
    pub fn has_input_option(&self) -> bool {
        self.options.lock().unwrap().iter().any(|(_, opt)| opt.is_input_var())
    }

    /// Add the input option, if not already present.
    ///
    /// Port of `addInputOption()`.
    pub fn add_input_option(&self) {
        if !self.has_input_option() {
            self.add_option(
                BlockFlow::entry(self.block),
                Arc::new(JitInputVar::new(self.out.varnode())),
            );
        }
    }

    /// The input operand use-def nodes, i.e. each option's value, in insertion order.
    ///
    /// Port of `inputs()`.
    ///
    /// # Note
    ///
    /// While this implies caring about some defined order, it's only so that the type of each
    /// operand can be derived. They all take the [`JitTypeBehavior::Copy`] type, so it's not a
    /// concern.
    pub fn inputs(&self) -> Vec<Arc<dyn JitVal>> {
        self.options.lock().unwrap().iter().map(|(_, opt)| Arc::clone(opt)).collect()
    }

    /// We do not require a particular type for the value, but we note the result is the same.
    ///
    /// Port of `optionType()`.
    pub fn option_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Copy
    }
}

impl JitOp for JitPhiOp {
    /// Port of `typeFor(int)`.
    fn type_for(&self, position: i32) -> JitTypeBehavior {
        let len = self.options.lock().unwrap().len() as i32;
        if position > len || position < 0 {
            panic!("AssertionError");
        }
        self.option_type()
    }

    /// Port of `link()`.
    fn link(&self) {
        self.out.set_definition(Some(self as &dyn JitDefOp));
        for (_, input) in self.options.lock().unwrap().iter() {
            input.add_use(self, 0);
        }
    }

    /// Port of `unlink()`.
    fn unlink(&self) {
        let is_mine = self.out.definition().is_some_and(|def| {
            std::ptr::eq(
                Arc::as_ptr(&def) as *const (),
                self as *const Self as *const (),
            )
        });
        if is_mine {
            self.out.set_definition(None);
        }
        for (_, input) in self.options.lock().unwrap().iter() {
            input.remove_use(self, 0);
        }
    }

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_phi_op(self);
    }
}

impl JitDefOp for JitPhiOp {
    /// Port of the record accessor `out()`.
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
    }

    /// Port of `type()`.
    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Copy
    }
}

impl JitSyntheticOp for JitPhiOp {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;
    use std::sync::Mutex as StdMutex;

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    struct MockOutVar {
        varnode: Varnode,
        definition: StdMutex<Option<Arc<dyn JitDefOp>>>,
        set_definition_calls: StdMutex<Vec<bool>>,
    }

    impl MockOutVar {
        fn new(varnode: Varnode) -> Self {
            Self {
                varnode,
                definition: StdMutex::new(None),
                set_definition_calls: StdMutex::new(Vec::new()),
            }
        }
    }

    impl JitOutVar for MockOutVar {
        fn set_definition(&self, definition: Option<&dyn JitDefOp>) {
            self.set_definition_calls.lock().unwrap().push(definition.is_some());
        }

        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            self.definition.lock().unwrap().clone()
        }

        fn varnode(&self) -> Varnode {
            self.varnode.clone()
        }
    }

    #[derive(Default)]
    struct MockVal {
        // (was_add, position) per call, in order.
        calls: StdMutex<Vec<(bool, i32)>>,
    }

    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            4
        }

        fn add_use(&self, _op: &dyn JitOp, position: i32) {
            self.calls.lock().unwrap().push((true, position));
        }

        fn remove_use(&self, _op: &dyn JitOp, position: i32) {
            self.calls.lock().unwrap().push((false, position));
        }
    }

    #[test]
    fn new_phi_has_no_options_and_no_input_option() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let phi = JitPhiOp::new(JitBlock::new(), out);

        assert!(!phi.has_input_option());
        assert!(phi.inputs().is_empty());
    }

    #[test]
    fn add_input_option_is_idempotent() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let block = JitBlock::new();
        let phi = JitPhiOp::new(block, out);

        phi.add_input_option();
        assert!(phi.has_input_option());
        assert_eq!(phi.inputs().len(), 1);

        // Java: addInputOption() only adds once, guarded by hasInputOption().
        phi.add_input_option();
        assert_eq!(phi.inputs().len(), 1);
    }

    #[test]
    fn add_option_registers_a_use_at_position_zero() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let block = JitBlock::new();
        let phi = JitPhiOp::new(block, out);

        let val = Arc::new(MockVal::default());
        phi.add_option(BlockFlow::entry(block), Arc::clone(&val) as Arc<dyn JitVal>);

        assert_eq!(phi.inputs().len(), 1);
        assert_eq!(&*val.calls.lock().unwrap(), &[(true, 0)]);
    }

    #[test]
    fn type_for_returns_copy_within_bounds() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let block = JitBlock::new();
        let val1: Arc<dyn JitVal> = Arc::new(MockVal::default());
        let val2: Arc<dyn JitVal> = Arc::new(MockVal::default());
        let phi = JitPhiOp::with_options(
            block,
            out,
            vec![(BlockFlow::entry(block), val1), (BlockFlow::entry(block), val2)],
        );

        // Java: `position > options.size()` is the failure condition, so `position ==
        // options.size()` (here 2) is still in bounds.
        assert_eq!(phi.type_for(0), JitTypeBehavior::Copy);
        assert_eq!(phi.type_for(2), JitTypeBehavior::Copy);
    }

    #[test]
    #[should_panic(expected = "AssertionError")]
    fn type_for_panics_past_option_count() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let phi = JitPhiOp::new(JitBlock::new(), out);
        phi.type_for(1);
    }

    #[test]
    #[should_panic(expected = "AssertionError")]
    fn type_for_panics_on_negative_position() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let phi = JitPhiOp::new(JitBlock::new(), out);
        phi.type_for(-1);
    }

    #[test]
    fn option_type_and_def_op_type_are_copy() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let phi = JitPhiOp::new(JitBlock::new(), out);

        assert_eq!(phi.option_type(), JitTypeBehavior::Copy);
        assert_eq!(JitDefOp::type_(&phi), JitTypeBehavior::Copy);
    }

    #[test]
    fn link_sets_definition_and_adds_uses_to_each_option() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let block = JitBlock::new();
        let val1 = Arc::new(MockVal::default());
        let val2 = Arc::new(MockVal::default());
        let phi = JitPhiOp::with_options(
            block,
            Arc::clone(&out) as Arc<dyn JitOutVar>,
            vec![
                (BlockFlow::entry(block), Arc::clone(&val1) as Arc<dyn JitVal>),
                (BlockFlow::entry(block), Arc::clone(&val2) as Arc<dyn JitVal>),
            ],
        );

        phi.link();

        assert_eq!(&*out.set_definition_calls.lock().unwrap(), &[true]);
        assert_eq!(&*val1.calls.lock().unwrap(), &[(true, 0)]);
        assert_eq!(&*val2.calls.lock().unwrap(), &[(true, 0)]);
    }

    #[test]
    fn unlink_clears_definition_only_if_still_the_definer_and_removes_uses() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar::new(varnode(&space, 0x1000, 4)));
        let block = JitBlock::new();
        let val = Arc::new(MockVal::default());
        let phi = Arc::new(JitPhiOp::with_options(
            block,
            Arc::clone(&out) as Arc<dyn JitOutVar>,
            vec![(BlockFlow::entry(block), Arc::clone(&val) as Arc<dyn JitVal>)],
        ));

        // Case 1: some other op currently defines `out` -- unlink must not touch it.
        phi.unlink();
        assert!(out.set_definition_calls.lock().unwrap().is_empty());
        assert_eq!(&*val.calls.lock().unwrap(), &[(false, 0)]);

        // Case 2: `phi` currently defines `out` (as `link()` would have arranged) -- unlink
        // must clear it.
        *out.definition.lock().unwrap() = Some(Arc::clone(&phi) as Arc<dyn JitDefOp>);
        phi.unlink();
        assert_eq!(&*out.set_definition_calls.lock().unwrap(), &[false]);
        assert_eq!(&*val.calls.lock().unwrap(), &[(false, 0), (false, 0)]);
    }
}
