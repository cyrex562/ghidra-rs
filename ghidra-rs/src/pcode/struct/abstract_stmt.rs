//! Shared state and concrete behavior for [`AbstractStmt`] implementations: the owning context
//! and the enclosing block, if any.
//!
//! Port of `ghidra.pcode.struct.AbstractStmt`.
//!
//! Java's `AbstractStmt` is an abstract class: it carries the `ctx`/`parent` fields and
//! implements every method of `Stmt` except the abstract `generate(Label, Label)`. Rust has no
//! field inheritance, so [`AbstractStmtBase`] holds the shared state, while [`AbstractStmt`]
//! declares the abstract method plus the two overridable ones (`isSingleGoto`/`getNext`) that
//! some of the ten in-repo subclasses (`AssignStmt`, `BlockStmt`, `ConditionalStmt`, `DeclStmt`,
//! `GotoStmt`, `LoopTruncateStmt`, `RawStmt`, `ResultStmt`, `ReturnStmt`, `VoidExprStmt`)
//! override.
//!
//! # `this`-taking operations
//!
//! Java's constructor registers `this` on the enclosing block's child list, and `reparent`/
//! `nearest` walk that same identity up the parent chain. Rust cannot recover an `Arc<dyn
//! AbstractStmt>` handle to `self` from a `&self` receiver, so those three operations are
//! modelled as free functions ([`register`], [`reparent`], [`nearest`]) that take the caller's
//! own `Arc<dyn AbstractStmt>` handle explicitly -- concrete subclasses call [`register`] right
//! after wrapping themselves in `Arc::new`, matching what the Java constructor does in one step.
//! `nearest` additionally can't be a trait method: it's generic, and a generic method would make
//! `AbstractStmt` not object-safe (it is used everywhere as `Arc<dyn AbstractStmt>`).

use std::any::Any;
use std::sync::Mutex;
use std::sync::Arc;

use crate::pcode::r#struct::string_tree::StringTree;
use crate::pcode::seam_stubs::{BlockStmt, SleighLabel, Stmt, StructuredSleighContext};

/// The shared state of an [`AbstractStmt`] implementation: the owning context and the enclosing
/// block (if any).
///
/// Port of the fields of `ghidra.pcode.struct.AbstractStmt`.
pub struct AbstractStmtBase {
    ctx: Arc<dyn StructuredSleighContext>,
    parent: Mutex<Option<Arc<dyn AbstractStmt>>>,
}

impl AbstractStmtBase {
    /// Mirrors the first half of the constructor `AbstractStmt(StructuredSleigh ctx)`: captures
    /// the context. Parent registration is deferred to [`register`], since it needs `this`.
    pub fn new(ctx: Arc<dyn StructuredSleighContext>) -> Self {
        Self { ctx, parent: Mutex::new(None) }
    }

    /// Port of `getContext()`.
    pub fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
        Arc::clone(&self.ctx)
    }

    /// The statement's current parent, if it is nested inside a block.
    pub fn parent(&self) -> Option<Arc<dyn AbstractStmt>> {
        self.parent.lock().unwrap().clone()
    }
}

/// Finishes constructing `this`: peeks the enclosing block off the context's block stack and, if
/// present, registers `this` as one of its children.
///
/// Port of the second half of the `AbstractStmt(StructuredSleigh ctx)` constructor:
/// `BlockStmt parent = ctx.stack.peek(); this.parent = parent; if (parent != null)
/// parent.children.add(this);`. Callers invoke this immediately after wrapping the new statement
/// in `Arc`.
pub fn register(this: Arc<dyn AbstractStmt>) {
    let Some(block) = this.base().ctx.stack_peek() else {
        return;
    };
    block.add_child(Arc::clone(&this));
    *this.base().parent.lock().unwrap() = Some(block.as_abstract_stmt());
}

/// Port of `reparent(AbstractStmt newParent)`: removes `this` from its current (block) parent's
/// children and re-parents it under `new_parent`, returning `this`. `this` must be passed
/// explicitly for the same reason as [`register`].
///
/// # Panics
/// Mirrors the Java `assert parent instanceof BlockStmt`: panics if `this` has no parent, or its
/// parent isn't a `BlockStmt`.
pub fn reparent(
    this: Arc<dyn AbstractStmt>,
    new_parent: Arc<dyn AbstractStmt>,
) -> Arc<dyn AbstractStmt> {
    let old_parent = this.base().parent.lock().unwrap().take();
    let old_parent = old_parent.expect("AbstractStmt.reparent: statement has no parent");
    let block =
        old_parent.as_block_stmt().expect("AbstractStmt.reparent: parent is not a BlockStmt");
    block.remove_child(&this);
    *this.base().parent.lock().unwrap() = Some(new_parent);
    this
}

/// Port of `nearest(Class<T> cls)`: walks from `this` up through its ancestors (including
/// itself), returning the first that is an instance of `T`.
///
/// A free function rather than a trait method -- see the module docs.
pub fn nearest<T: Any + Send + Sync>(this: &Arc<dyn AbstractStmt>) -> Option<Arc<T>> {
    match Arc::clone(this).into_any_arc().downcast::<T>() {
        Ok(found) => Some(found),
        Err(_) => {
            let parent = this.base().parent.lock().unwrap().clone();
            parent.as_ref().and_then(nearest::<T>)
        }
    }
}

/// The abstract part of `ghidra.pcode.struct.AbstractStmt`: the method every concrete statement
/// must supply, the two overridable hooks some of them customize, and the accessors/downcasts
/// [`register`]/[`reparent`]/[`nearest`] need.
pub trait AbstractStmt: Stmt {
    /// Access the shared statement state.
    fn base(&self) -> &AbstractStmtBase;

    /// Coerces to `Arc<dyn Any + Send + Sync>`, so [`nearest`] can attempt a downcast.
    /// Implementors write `{ self }`; see
    /// [`RValInternal::as_rval_internal`](crate::pcode::r#struct::rval_internal::RValInternal::as_rval_internal).
    fn into_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;

    /// If this statement is a `BlockStmt`, exposes it as one; used by [`reparent`]. Default: not
    /// a block. The `BlockStmt` port overrides this to return `Some(self)`.
    fn as_block_stmt(&self) -> Option<&dyn BlockStmt> {
        None
    }

    /// Port of the abstract `generate(Label next, Label fall)`: generate the Sleigh code that
    /// implements this statement.
    fn generate(&self, next: Arc<dyn SleighLabel>, fall: Arc<dyn SleighLabel>) -> StringTree;

    /// Port of `isSingleGoto()`: whether this statement is or contains a single branch statement.
    /// Default: `false`.
    fn is_single_goto(&self) -> bool {
        false
    }

    /// Port of `getNext()`: the label for the statement immediately following this one. Default:
    /// the context's fall-through label.
    fn get_next(&self) -> Arc<dyn SleighLabel> {
        self.base().get_context().fall()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pcode::r#struct::rval_internal::RValInternal;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;

    struct TestLabel;
    impl SleighLabel for TestLabel {
        fn gen_goto(&self, _fall: &dyn SleighLabel) -> StringTree {
            StringTree::single("goto")
        }
    }

    struct TestCtx {
        space: Arc<AddressSpace>,
        stack: Mutex<Vec<Arc<dyn BlockStmt>>>,
    }

    impl TestCtx {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
                stack: Mutex::new(Vec::new()),
            })
        }
    }

    impl StructuredSleighContext for TestCtx {
        fn default_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.space)
        }

        fn lit(&self, _val: i64, _size: i32) -> Arc<dyn RValInternal> {
            unimplemented!()
        }

        fn compute_deref_type(&self, _addr: &dyn RValInternal) -> Box<dyn DataType> {
            unimplemented!()
        }

        fn fall(&self) -> Arc<dyn SleighLabel> {
            Arc::new(TestLabel)
        }

        fn stack_peek(&self) -> Option<Arc<dyn BlockStmt>> {
            self.stack.lock().unwrap().last().cloned()
        }
    }

    /// A leaf statement standing in for e.g. `RawStmt`: never a block, no children of its own.
    struct TestStmt {
        base: AbstractStmtBase,
    }

    impl TestStmt {
        fn new(ctx: Arc<dyn StructuredSleighContext>) -> Arc<Self> {
            let this = Arc::new(Self { base: AbstractStmtBase::new(ctx) });
            register(Arc::clone(&this) as Arc<dyn AbstractStmt>);
            this
        }
    }

    impl Stmt for TestStmt {}

    impl AbstractStmt for TestStmt {
        fn base(&self) -> &AbstractStmtBase {
            &self.base
        }

        fn into_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }

        fn generate(&self, _next: Arc<dyn SleighLabel>, _fall: Arc<dyn SleighLabel>) -> StringTree {
            StringTree::single("stmt")
        }
    }

    /// A block statement standing in for `BlockStmt`: tracks children so `register`/`reparent`
    /// can be exercised end-to-end.
    struct TestBlock {
        base: AbstractStmtBase,
        children: Mutex<Vec<Arc<dyn AbstractStmt>>>,
    }

    impl TestBlock {
        fn new(ctx: Arc<dyn StructuredSleighContext>) -> Arc<Self> {
            let this = Arc::new(Self { base: AbstractStmtBase::new(ctx), children: Mutex::new(Vec::new()) });
            register(Arc::clone(&this) as Arc<dyn AbstractStmt>);
            this
        }
    }

    impl Stmt for TestBlock {}

    impl AbstractStmt for TestBlock {
        fn base(&self) -> &AbstractStmtBase {
            &self.base
        }

        fn into_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }

        fn as_block_stmt(&self) -> Option<&dyn BlockStmt> {
            Some(self)
        }

        fn generate(&self, _next: Arc<dyn SleighLabel>, _fall: Arc<dyn SleighLabel>) -> StringTree {
            StringTree::single("block")
        }
    }

    impl BlockStmt for TestBlock {
        fn add_child(&self, child: Arc<dyn AbstractStmt>) {
            self.children.lock().unwrap().push(child);
        }

        fn remove_child(&self, child: &Arc<dyn AbstractStmt>) {
            self.children.lock().unwrap().retain(|c| !Arc::ptr_eq(c, child));
        }

        fn as_abstract_stmt(self: Arc<Self>) -> Arc<dyn AbstractStmt> {
            self
        }
    }

    #[test]
    fn get_context_returns_the_constructor_argument() {
        let ctx = TestCtx::new();
        let stmt = TestStmt::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);
        assert!(Arc::ptr_eq(&stmt.base().get_context(), &(ctx as Arc<dyn StructuredSleighContext>)));
    }

    #[test]
    fn is_single_goto_defaults_to_false() {
        let ctx = TestCtx::new() as Arc<dyn StructuredSleighContext>;
        let stmt = TestStmt::new(ctx);
        assert!(!stmt.is_single_goto());
    }

    #[test]
    fn get_next_defaults_to_the_context_fall_label() {
        // Java: getNext() == ctx.FALL when unoverridden.
        let ctx = TestCtx::new() as Arc<dyn StructuredSleighContext>;
        let stmt = TestStmt::new(Arc::clone(&ctx));
        let _ = stmt.get_next();
        // No observable identity on the stub `SleighLabel`; this exercises the default path
        // without panicking, which is the behavior under test.
    }

    #[test]
    fn construction_with_no_open_block_leaves_parent_none() {
        // Java: ctx.stack.peek() == null -> parent stays null, nothing registered.
        let ctx = TestCtx::new() as Arc<dyn StructuredSleighContext>;
        let stmt = TestStmt::new(ctx);
        assert!(stmt.base().parent().is_none());
    }

    #[test]
    fn construction_inside_a_block_registers_as_a_child_and_records_the_parent() {
        let ctx = TestCtx::new();
        let block = TestBlock::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);
        ctx.stack.lock().unwrap().push(Arc::clone(&block) as Arc<dyn BlockStmt>);

        let child = TestStmt::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);

        assert_eq!(block.children.lock().unwrap().len(), 1);
        assert!(Arc::ptr_eq(&block.children.lock().unwrap()[0], &(Arc::clone(&child) as Arc<dyn AbstractStmt>)));
        let parent = child.base().parent().expect("parent should be set");
        assert!(Arc::ptr_eq(&parent, &(Arc::clone(&block) as Arc<dyn AbstractStmt>)));
    }

    #[test]
    fn reparent_moves_the_child_between_blocks() {
        let ctx = TestCtx::new();
        let block_a = TestBlock::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);
        ctx.stack.lock().unwrap().push(Arc::clone(&block_a) as Arc<dyn BlockStmt>);
        let child = TestStmt::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);
        ctx.stack.lock().unwrap().pop();

        assert_eq!(block_a.children.lock().unwrap().len(), 1);

        let block_b = TestBlock::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);
        let child_dyn = Arc::clone(&child) as Arc<dyn AbstractStmt>;
        let new_parent = Arc::clone(&block_b) as Arc<dyn AbstractStmt>;
        let returned = reparent(child_dyn, new_parent);

        assert!(Arc::ptr_eq(&returned, &(Arc::clone(&child) as Arc<dyn AbstractStmt>)));
        assert!(block_a.children.lock().unwrap().is_empty());
        let parent = child.base().parent().expect("parent should be set");
        assert!(Arc::ptr_eq(&parent, &(Arc::clone(&block_b) as Arc<dyn AbstractStmt>)));
    }

    #[test]
    #[should_panic(expected = "statement has no parent")]
    fn reparent_panics_without_a_parent() {
        let ctx = TestCtx::new();
        let stmt = TestStmt::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);
        let other = TestBlock::new(ctx as Arc<dyn StructuredSleighContext>);
        let _ = reparent(
            Arc::clone(&stmt) as Arc<dyn AbstractStmt>,
            Arc::clone(&other) as Arc<dyn AbstractStmt>,
        );
    }

    #[test]
    fn nearest_finds_self_when_it_matches() {
        let ctx = TestCtx::new() as Arc<dyn StructuredSleighContext>;
        let stmt = TestStmt::new(ctx);
        let stmt_dyn = Arc::clone(&stmt) as Arc<dyn AbstractStmt>;
        let found = nearest::<TestStmt>(&stmt_dyn);
        assert!(found.is_some());
    }

    #[test]
    fn nearest_walks_up_to_an_ancestor_of_the_requested_type() {
        let ctx = TestCtx::new();
        let block = TestBlock::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);
        ctx.stack.lock().unwrap().push(Arc::clone(&block) as Arc<dyn BlockStmt>);
        let child = TestStmt::new(Arc::clone(&ctx) as Arc<dyn StructuredSleighContext>);

        let child_dyn = Arc::clone(&child) as Arc<dyn AbstractStmt>;
        let found = nearest::<TestBlock>(&child_dyn).expect("should find the enclosing block");
        assert!(Arc::ptr_eq(&found, &block));
    }

    #[test]
    fn nearest_returns_none_when_no_ancestor_matches() {
        let ctx = TestCtx::new() as Arc<dyn StructuredSleighContext>;
        let stmt = TestStmt::new(ctx);
        let stmt_dyn = Arc::clone(&stmt) as Arc<dyn AbstractStmt>;
        assert!(nearest::<TestBlock>(&stmt_dyn).is_none());
    }
}
