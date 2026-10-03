//! Port of `ghidra.lisa.pcode.contexts.HighStatementContext`.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use crate::feature::lisa::pcode::contexts::condition_context::ConditionContext;
use crate::feature::lisa::pcode::contexts::pcode_context::PcodeContext;
use crate::feature::lisa::pcode::contexts::statement_context::StatementContext;
use crate::feature::lisa::pcode::contexts::var_def_context::VarDefContext;
use crate::program::model::address::AddressFactory;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::PcodeOp;

/// Shared, mutably-linkable handle to a [`HighStatementContext`], standing in for Java's plain
/// object references in [`HighStatementContext::prev`]/[`HighStatementContext::succ`] (two
/// `HighStatementContext`s can each point at the same neighbor, forming a shared doubly-linked
/// chain as `PcodeCodeMemberVisitor` builds it up). Follows this crate's established convention
/// for this shape (see `framework::db::buffers::buffer_node::BufferNodeRef`, `Rc<RefCell<dyn
/// BufferNode>>`).
pub type HighStatementContextRef = Rc<RefCell<HighStatementContext>>;

/// A [`StatementContext`] specialized for high (decompiler-recovered) p-code, additionally
/// tracking the owning [`HighFunction`] and this statement's position in a doubly-linked chain of
/// sibling statements plus any branch targets.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.HighStatementContext` in the Java source, which
/// `extends StatementContext`. Following this crate's composition-over-inheritance convention,
/// this wraps a `StatementContext` by composition instead, re-exposing the members Java inherits
/// unmodified and providing its own [`fmt::Display`]/[`HighStatementContext::get_address_factory`]
/// in place of the ones Java overrides.
pub struct HighStatementContext {
    base: StatementContext,
    hfunc: Arc<dyn HighFunction>,
    /// Mirrors the Java class's private `prev` field.
    prev: Option<HighStatementContextRef>,
    /// Mirrors the Java class's private `succ` field (exposed via `getNext()`/`setNext()`).
    succ: Option<HighStatementContextRef>,
    /// Mirrors the Java class's private `branches` field (`new ArrayList<>()`, i.e. it always
    /// starts empty, never `null`).
    branches: Vec<StatementContext>,
}

impl HighStatementContext {
    /// Java: `HighStatementContext(HighFunction hfunc, PcodeOp op)`, which delegates `super(op)`
    /// to the protected `StatementContext(PcodeOp op)` constructor (ported as
    /// [`StatementContext::from_op`]) -- never the public 2-arg constructor, so this context's
    /// `inst` starts (and, absent something reaching in to set it, stays) absent, exactly as
    /// [`StatementContext`]'s own docs describe for that constructor's other real callers.
    pub fn new(hfunc: Arc<dyn HighFunction>, op: PcodeOp) -> Self {
        Self {
            base: StatementContext::from_op(op),
            hfunc,
            prev: None,
            succ: None,
            branches: Vec::new(),
        }
    }

    /// Java: the inherited `getOp()`.
    pub fn get_op(&self) -> &PcodeOp {
        self.base.get_op()
    }

    /// Java: the inherited `target()`. See [`StatementContext::target`]'s own docs for when this
    /// panics.
    pub fn target(&self) -> &VarDefContext {
        self.base.target()
    }

    /// Java: the inherited `expression()`.
    pub fn expression(&self) -> &PcodeContext {
        self.base.expression()
    }

    /// Java: the inherited `condition()`.
    pub fn condition(&self) -> ConditionContext {
        self.base.condition()
    }

    /// Java: the inherited `isRet()`.
    pub fn is_ret(&self) -> bool {
        self.base.is_ret()
    }

    /// Java: the inherited `isBranch()`.
    pub fn is_branch(&self) -> bool {
        self.base.is_branch()
    }

    /// Java: the inherited `isConditional()`.
    pub fn is_conditional(&self) -> bool {
        self.base.is_conditional()
    }

    /// Java: the overridden `getAddressFactory()`, `return hfunc.getAddressFactory();` -- unlike
    /// the base [`StatementContext::get_address_factory`] (which threads through `inst`'s
    /// program, and panics if `inst` is absent), this override reads straight from the owning
    /// [`HighFunction`], so it never touches `inst` at all.
    pub fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        self.hfunc.get_address_factory()
    }

    /// Java: `getPrev()`.
    pub fn get_prev(&self) -> Option<HighStatementContextRef> {
        self.prev.clone()
    }

    /// Java: `setPrev(HighStatementContext ctx)`.
    pub fn set_prev(&mut self, ctx: HighStatementContextRef) {
        self.prev = Some(ctx);
    }

    /// Java: `getNext()`.
    pub fn get_next(&self) -> Option<HighStatementContextRef> {
        self.succ.clone()
    }

    /// Java: `setNext(HighStatementContext ctx)`.
    pub fn set_next(&mut self, ctx: HighStatementContextRef) {
        self.succ = Some(ctx);
    }

    /// Java: `getBranches()`.
    pub fn get_branches(&self) -> &[StatementContext] {
        &self.branches
    }

    /// Java: `addBranch(HighStatementContext ctx)`, `branches.add(ctx);` -- Java adds the whole
    /// `HighStatementContext` into a `List<StatementContext>`, relying on `HighStatementContext
    /// extends StatementContext` to upcast it; only the `StatementContext`-level API remains
    /// reachable through that list afterward (`getBranches()` is typed `List<StatementContext>`,
    /// not `List<HighStatementContext>`). This port models the same narrowing explicitly: `ctx`
    /// is consumed by value and only its composed [`StatementContext`] is kept.
    pub fn add_branch(&mut self, ctx: HighStatementContext) {
        self.branches.push(ctx.base);
    }
}

impl fmt::Display for HighStatementContext {
    /// Java: the overridden `toString()`, `return op.getSeqnum() + ": " + op;` -- reads the
    /// inherited (protected) `op` field directly, unlike the base
    /// [`StatementContext`]'s own `toString()` (which also needs `inst`, and panics without it).
    /// This override never touches `inst`, so it never panics for that reason.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = self.base.get_op();
        write!(f, "{}: {}", op.get_seqnum(), op)
    }
}

impl fmt::Debug for HighStatementContext {
    /// Manual `Debug` impl: `hfunc` is `Arc<dyn HighFunction>`, which does not require `Debug`
    /// (the same "trait object with no Debug supertrait" situation
    /// [`StatementContext`]'s own manual `Debug` impl describes), and `prev`/`succ` hold `Rc<RefCell<Self>>`
    /// cycles that a derived recursive `Debug` could loop over. Reports structure without
    /// recursing into linked neighbors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HighStatementContext")
            .field("op", self.base.get_op())
            .field("has_prev", &self.prev.is_some())
            .field("has_next", &self.succ.is_some())
            .field("branches", &self.branches.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Function;
    use crate::program::model::pcode::{OpCode, SequenceNumber, Varnode};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(space.clone(), offset), size)
    }

    fn op_with(opcode: OpCode, inputs: Vec<Varnode>, output: Option<Varnode>) -> PcodeOp {
        let space = ram_space();
        let seq = SequenceNumber::new(Address::new(space, 0x1000), 0);
        PcodeOp::new(opcode, seq, inputs, output)
    }

    /// A minimal `HighFunction` mock overriding `get_address_factory` directly, so tests don't
    /// need to build a full `Function`/`Program` mock chain just to control what it returns (see
    /// the trait's own default body: `self.get_function().get_program().get_address_factory()`).
    struct MockHighFunction {
        address_factory: Option<Arc<dyn AddressFactory>>,
    }

    impl HighFunction for MockHighFunction {
        fn get_function(&self) -> Box<dyn Function> {
            unimplemented!("not exercised by these tests -- get_address_factory is overridden")
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn get_local_symbol_map(&self) -> Box<dyn crate::program::seam_stubs::LocalSymbolMap> {
            unimplemented!("not exercised by these tests")
        }
        fn get_global_symbol_map(
            &self,
        ) -> Arc<dyn crate::program::model::pcode::global_symbol_map::GlobalSymbolMap> {
            unimplemented!("not exercised by these tests")
        }
        fn grab_from_function(
            &mut self,
            _override_extrapop: i32,
            _include_default_names: bool,
            _do_override: bool,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn decode(
            &mut self,
            _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
        ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
            unimplemented!("not exercised by these tests")
        }
        fn split_out_merge_group(
            &mut self,
            _high: Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
            _vn: &Varnode,
        ) -> Result<
            Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
            crate::program::model::pcode::pcode_exception::PcodeException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn encode(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder,
            _id: i64,
            _namespace: &dyn crate::program::model::symbol::Namespace,
            _entry_point: Option<Address>,
            _size: i32,
        ) -> std::io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
        fn set_volatile(&mut self, _vn: &Varnode, _val: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            self.address_factory.clone()
        }
    }

    #[test]
    fn new_derives_opcode_and_right_from_op_via_the_base_statement_context() {
        let space = ram_space();
        let output = varnode(&space, 0x10, 4);
        let op = op_with(OpCode::Copy, vec![varnode(&space, 0x20, 4)], Some(output.clone()));
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { address_factory: None });

        let ctx = HighStatementContext::new(hfunc, op);

        assert_eq!(ctx.target().varnode(), &output);
        assert!(!ctx.is_ret());
    }

    #[test]
    fn get_address_factory_reads_through_hfunc_not_inst() {
        let ram = ram_space();
        let factory = crate::program::model::address::DefaultAddressFactory::with_default_space(
            vec![ram.clone()],
            Some(ram),
        );
        let factory: Arc<dyn AddressFactory> = Arc::new(factory);
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let hfunc: Arc<dyn HighFunction> =
            Arc::new(MockHighFunction { address_factory: Some(factory.clone()) });

        let ctx = HighStatementContext::new(hfunc, op);

        // No `inst` was ever set (see `new`'s docs), yet `get_address_factory` still succeeds --
        // proving it reads through `hfunc`, not `inst`/`inst.getProgram()` like the base
        // `StatementContext::get_address_factory` does.
        assert!(ctx.get_address_factory().is_some());
    }

    #[test]
    fn display_renders_seqnum_and_op_without_needing_inst() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let op_clone = op.clone();
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { address_factory: None });

        let ctx = HighStatementContext::new(hfunc, op);

        let expected = format!("{}: {}", op_clone.get_seqnum(), op_clone);
        assert_eq!(ctx.to_string(), expected);
    }

    #[test]
    fn prev_and_next_start_as_none_and_round_trip_through_setters() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { address_factory: None });
        let ctx = Rc::new(RefCell::new(HighStatementContext::new(hfunc.clone(), op)));

        assert!(ctx.borrow().get_prev().is_none());
        assert!(ctx.borrow().get_next().is_none());

        let neighbor_op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 4, 4)));
        let neighbor = Rc::new(RefCell::new(HighStatementContext::new(hfunc, neighbor_op)));

        ctx.borrow_mut().set_prev(neighbor.clone());
        ctx.borrow_mut().set_next(neighbor.clone());

        assert!(Rc::ptr_eq(&ctx.borrow().get_prev().unwrap(), &neighbor));
        assert!(Rc::ptr_eq(&ctx.borrow().get_next().unwrap(), &neighbor));
    }

    #[test]
    fn branches_starts_empty_and_add_branch_keeps_only_the_statement_context_level_api() {
        let op = op_with(OpCode::Copy, vec![], Some(varnode(&ram_space(), 0, 4)));
        let hfunc: Arc<dyn HighFunction> = Arc::new(MockHighFunction { address_factory: None });
        let mut ctx = HighStatementContext::new(hfunc.clone(), op);
        assert!(ctx.get_branches().is_empty());

        let branch_target = varnode(&ram_space(), 8, 4);
        let branch_op = op_with(OpCode::Copy, vec![], Some(branch_target.clone()));
        let branch = HighStatementContext::new(hfunc, branch_op);

        ctx.add_branch(branch);

        assert_eq!(ctx.get_branches().len(), 1);
        assert_eq!(ctx.get_branches()[0].target().varnode(), &branch_target);
    }
}
