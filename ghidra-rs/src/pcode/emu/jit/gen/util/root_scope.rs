//! The root scope for local variable declarations.
//!
//! Port of `ghidra.pcode.emu.jit.gen.util.RootScope`.
//!
//! Each generated method has exactly one root scope, opened when its [`Emitter`] is created and
//! closed once code generation for the method is finished. Temporary scopes nested inside it are
//! opened with [`RootScope::sub`].

use crate::pcode::emu::jit::gen::util::lbl::{Lbl, LblEm};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::sub_scope::SubScope;
use crate::pcode::emu::jit::gen::util::types::BNonVoid;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Next};
use crate::pcode::seam_stubs::{ChildScope, Scope};

/// A local variable declaration recorded by [`RootScope::decl`], kept around only so
/// [`RootScope::close`] can later hand it to the emitter.
///
/// Java keeps the original `Local<?>` (a wildcard-typed record) in `RootScope.vars` and replays
/// `Local.decl` over each entry when the scope closes. A `Vec` can't hold `Local<T>` for varying
/// `T` in Rust, so this projects out exactly what `Local::decl` reads -- name, JVM descriptor, and
/// index -- at declaration time instead.
struct DeclaredVar {
    name: String,
    descriptor: String,
    index: i32,
}

/// The root scope for local variable declarations in a generated method.
///
/// Port of `ghidra.pcode.emu.jit.gen.util.RootScope<N>`. `N` is the stack shape at the scope's
/// start and finish (not statically enforced, as in Java).
///
/// In Java this class is extended by `ChildScope` to implement [`RootScope::sub`]. Rust has no
/// class inheritance, so `ChildScope` will instead wrap a `RootScope` by composition once it is
/// ported; until then, [`SubScope`] is served by the minimal placeholder in
/// [`crate::pcode::seam_stubs::ChildScope`].
pub struct RootScope<N> {
    em: Emitter<N>,
    start: Lbl<N>,
    next_local: i32,
    /// Whether a child scope opened by [`RootScope::sub`] is currently active.
    ///
    /// Java tracks this with a `childScope` field of type `Scope`, set directly by `ChildScope`'s
    /// constructor (package-private field access) and cleared by its `close`. `ChildScope` is not
    /// ported yet (see the cycle note on the struct docs), so nothing currently clears this flag
    /// once [`RootScope::sub`] sets it; that bookkeeping belongs to `ChildScope` once it exists.
    child_active: bool,
    closed: bool,
    vars: Vec<DeclaredVar>,
}

impl<N: Next> RootScope<N> {
    /// Construct a root scope wrapping the given emitter, starting local variable indices at
    /// `next_local`.
    ///
    /// Port of the package-private constructor `RootScope(Emitter<?>, int)`. Places the scope's
    /// start label immediately, as Java's constructor does via `Lbl.place(this.em)`.
    pub(crate) fn new(em: Emitter<N>, next_local: i32) -> Self {
        let LblEm { lbl: start, em } = Lbl::place(em);
        Self { em, start, next_local, child_active: false, closed: false, vars: Vec::new() }
    }

    /// Open a child scope of this scope, usually for temporary declarations.
    ///
    /// Port of `RootScope.sub`. Java returns `new ChildScope<>(em, this)`; since `ChildScope` is
    /// not ported yet, this returns the placeholder [`crate::pcode::seam_stubs::ChildScope`],
    /// which owns an independent `RootScope` continuing this scope's local-variable numbering.
    pub fn sub(&mut self) -> Box<dyn SubScope>
    where
        N: Send + Sync + Clone + 'static,
    {
        self.child_active = true;
        Box::new(ChildScope::new(RootScope::new(self.em.clone(), self.next_local)))
    }

    /// Declare a local variable in this scope.
    ///
    /// Port of `RootScope.decl`. Assigns the local the next available index, advancing the index
    /// by the type's slot count. Panics if a child scope is currently active, mirroring Java's
    /// `IllegalStateException("There is a child scope active.")`.
    pub fn decl<T: BNonVoid>(&mut self, type_: T, name: impl Into<String>) -> Local<T> {
        if self.child_active {
            panic!("There is a child scope active.");
        }
        let index = self.next(&type_);
        let local = Local::of(type_, name, index);
        self.vars.push(DeclaredVar {
            name: local.name.clone(),
            descriptor: local.type_.descriptor().to_string(),
            index: local.index,
        });
        local
    }

    /// Reserve the next local-variable index (or pair, for category-2 types) for `type_`.
    ///
    /// Port of `RootScope.next`.
    fn next<T: BNonVoid>(&mut self, type_: &T) -> i32 {
        let next = self.next_local;
        self.next_local += type_.slots() as i32;
        next
    }

    /// Declare every variable recorded by [`RootScope::decl`] in the wrapped emitter, scoped from
    /// this scope's start label to a freshly-placed end label.
    ///
    /// Port of `RootScope.declVars`.
    fn decl_vars(&mut self) {
        // Cloning an emitter yields another handle on the same method visitor, so this places the
        // end label and the declarations into the very visitor Java's `this.em` writes to.
        let LblEm { lbl: end, mut em } = Lbl::place(self.em.clone());
        for v in &self.vars {
            em.visit_local_variable(&v.name, &v.descriptor, self.start.label, end.label, v.index);
        }
        self.em = em;
    }

    /// Close this scope, declaring its local variables in the wrapped emitter.
    ///
    /// Port of `RootScope.close`. Idempotent: closing an already-closed scope is a no-op, as in
    /// Java.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.decl_vars();
        self.closed = true;
    }
}

impl<N: Send + Sync> Scope for RootScope<N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::types::{T_INT, T_LONG};

    #[derive(Clone, Copy)]
    struct StackShape;
    impl Next for StackShape {}

    #[test]
    fn decl_assigns_indices_by_slot_count() {
        let mut scope = RootScope::<StackShape>::new(Emitter::default(), 0);
        // int (T_INT) occupies 1 slot, so the next local starts right after it.
        let a = scope.decl(T_INT, "a");
        assert_eq!(a.index, 0);
        // long (T_LONG) occupies 2 slots.
        let b = scope.decl(T_LONG, "b");
        assert_eq!(b.index, 1);
        let c = scope.decl(T_INT, "c");
        assert_eq!(c.index, 3);
    }

    #[test]
    fn close_declares_recorded_vars_from_start_to_a_new_end_label() {
        let mut scope = RootScope::<StackShape>::new(Emitter::default(), 0);
        let start_label = scope.start.label;
        scope.decl(T_INT, "x");
        scope.decl(T_LONG, "y");

        scope.close();

        let declared = scope.em.local_variables();
        assert_eq!(declared.len(), 2);
        assert_eq!(declared[0], ("x".to_string(), "I".to_string(), start_label, declared[0].3, 0));
        assert_eq!(declared[1], ("y".to_string(), "J".to_string(), start_label, declared[1].3, 1));
        // Both vars share the same end label, placed once for the whole scope.
        assert_eq!(declared[0].3, declared[1].3);
    }

    #[test]
    fn close_is_idempotent() {
        let mut scope = RootScope::<StackShape>::new(Emitter::default(), 0);
        scope.decl(T_INT, "x");

        scope.close();
        let after_first = scope.em.local_variables().len();
        scope.close();
        let after_second = scope.em.local_variables().len();

        assert_eq!(after_first, 1);
        assert_eq!(after_second, 1);
    }

    #[test]
    #[should_panic(expected = "There is a child scope active.")]
    fn decl_panics_while_child_scope_active() {
        let mut scope = RootScope::<StackShape>::new(Emitter::default(), 0);
        let _child = scope.sub();
        scope.decl(T_INT, "x");
    }
}
