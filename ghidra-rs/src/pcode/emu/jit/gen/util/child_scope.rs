//! A child scope for local variable declarations.
//!
//! Port of `ghidra.pcode.emu.jit.gen.util.ChildScope`.
//!
//! Java's `ChildScope<N>` `extends RootScope<N>`, inheriting every one of its methods (`decl`,
//! `sub`, `close`) unchanged except `close`, and layers on exactly two things:
//!
//! * its constructor `ChildScope(Emitter<? extends Next>, RootScope<N> parentScope)` calls
//!   `super(em, parentScope.nextLocal)` (continuing the parent's local-variable numbering), then
//!   records itself as the parent's active child: `parentScope.childScope = this`;
//! * its overridden `close()` first runs the inherited close logic (`super.close()`), then clears
//!   that marker: `parentScope.childScope = null`.
//!
//! Rust has no class inheritance, so this port composes a private [`RootScope`] for the
//! "`extends RootScope<N>`" part (built by [`RootScope::sub`], the only place with access to the
//! parent's private fields), plus the one thing Java's `parentScope` back-reference is ever used
//! for: a flag the parent's [`RootScope::decl`] consults to refuse declaring a local while a child
//! scope is open. No other method reads `parentScope`, so a shared `Arc<AtomicBool>` reproduces its
//! entire observable footprint without needing a full back-reference to the parent object (which
//! would otherwise require `Rc<RefCell<RootScope<N>>>` throughout, a much larger change to the
//! already-ported [`RootScope`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::pcode::emu::jit::gen::util::emitter::Next;
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::root_scope::RootScope;
use crate::pcode::emu::jit::gen::util::sub_scope::SubScope;
use crate::pcode::emu::jit::gen::util::types::BNonVoid;
use crate::pcode::seam_stubs::Scope;

/// A child scope for local variable declarations, opened by [`RootScope::sub`].
///
/// Port of `ghidra.pcode.emu.jit.gen.util.ChildScope<N>`. `N` is the stack at scope start and
/// finish (not really enforced), inherited unchanged from the parent [`RootScope`].
pub struct ChildScope<N> {
    /// The composed "superclass" part: this scope's own local-variable bookkeeping, continuing
    /// the parent's numbering.
    ///
    /// Port of the fields `RootScope` contributes via `extends RootScope<N>`: `em`, `start`,
    /// `nextLocal`, `closed`, and `vars`.
    inner: RootScope<N>,
    /// The parent's active-child marker: set to `true` on construction, cleared on close. The
    /// sole observable use of Java's `protected final RootScope<N> parentScope` field.
    parent_active: Arc<AtomicBool>,
}

impl<N: Next> ChildScope<N> {
    /// Construct a child scope wrapping `inner` -- already opened over the parent's emitter,
    /// continuing the parent's local-variable numbering, exactly as Java's
    /// `super(em, parentScope.nextLocal)` does -- and record it as the owner of `parent_active`.
    ///
    /// Port of the package-private constructor `ChildScope(Emitter<? extends Next>,
    /// RootScope<N>)`. Java builds the superclass part itself and then reaches into
    /// `parentScope.childScope`; here [`RootScope::sub`] builds `inner` (it alone has access to
    /// the parent's private fields) and hands it to this constructor along with the parent's
    /// shared marker. Setting `parent_active` to `true` here reproduces
    /// `parentScope.childScope = this`.
    pub(crate) fn new(inner: RootScope<N>, parent_active: Arc<AtomicBool>) -> Self {
        parent_active.store(true, Ordering::SeqCst);
        Self { inner, parent_active }
    }

    /// Open a child scope of this scope, usually for temporary declarations.
    ///
    /// Port of the inherited `RootScope.sub()`.
    pub fn sub(&mut self) -> Box<dyn SubScope>
    where
        N: Send + Sync + Clone + 'static,
    {
        self.inner.sub()
    }

    /// Declare a local variable in this scope.
    ///
    /// Port of the inherited `RootScope.decl(T, String)`.
    pub fn decl<T: BNonVoid>(&mut self, type_: T, name: impl Into<String>) -> Local<T> {
        self.inner.decl(type_, name)
    }
}

impl<N: Send + Sync> Scope for ChildScope<N> {}

impl<N: Send + Sync + Next> SubScope for ChildScope<N> {
    /// Close this scope, then clear the parent's active-child marker.
    ///
    /// Port of `ChildScope.close()`:
    /// ```java
    /// public void close() {
    ///     super.close();
    ///     parentScope.childScope = null;
    /// }
    /// ```
    /// Note this clears the marker unconditionally on every call, even a second one -- Java's
    /// `RootScope.close()` guards its own `declVars()` re-run with a `closed` flag, but
    /// `ChildScope.close()` has no such guard of its own, so `parentScope.childScope = null` (here,
    /// `parent_active.set(false)`) runs again on a repeated close. That repetition is harmless
    /// (the marker is already clear), so it is reproduced faithfully rather than added a fresh
    /// guard Java itself does not have.
    fn close(&mut self) {
        self.inner.close();
        self.parent_active.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter};
    use crate::pcode::emu::jit::gen::util::types::{T_INT, T_LONG};

    #[test]
    fn constructing_a_child_marks_the_parent_flag_active() {
        let flag = Arc::new(AtomicBool::new(false));
        let inner = RootScope::<Bot>::new(Emitter::default(), 0);
        assert!(!flag.load(Ordering::SeqCst));

        let child = ChildScope::new(inner, Arc::clone(&flag));
        // Java: the ChildScope constructor sets `parentScope.childScope = this`.
        assert!(flag.load(Ordering::SeqCst));
        drop(child);
    }

    #[test]
    fn closing_a_child_clears_the_parent_flag() {
        let flag = Arc::new(AtomicBool::new(false));
        let inner = RootScope::<Bot>::new(Emitter::default(), 0);
        let mut child = ChildScope::new(inner, Arc::clone(&flag));
        assert!(flag.load(Ordering::SeqCst));

        child.close();

        // Java: `close()` runs `parentScope.childScope = null`.
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn closing_a_child_twice_clears_the_flag_both_times_harmlessly() {
        // Java's ChildScope.close() has no `closed`-style guard of its own around
        // `parentScope.childScope = null`, unlike the inherited RootScope.close()'s guard around
        // declVars(). So a second close() call still clears the (already-clear) flag.
        let flag = Arc::new(AtomicBool::new(false));
        let inner = RootScope::<Bot>::new(Emitter::default(), 0);
        let mut child = ChildScope::new(inner, Arc::clone(&flag));

        child.close();
        assert!(!flag.load(Ordering::SeqCst));
        child.close();
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn child_scope_continues_the_parents_local_numbering() {
        // Java: `super(em, parentScope.nextLocal)`.
        let flag = Arc::new(AtomicBool::new(false));
        let inner = RootScope::<Bot>::new(Emitter::default(), 5);
        let mut child = ChildScope::new(inner, flag);

        let a = child.decl(T_INT, "a");
        assert_eq!(a.index, 5);
        let b = child.decl(T_LONG, "b");
        assert_eq!(b.index, 6);
    }

    #[test]
    fn child_scope_can_open_its_own_grandchild() {
        let flag = Arc::new(AtomicBool::new(false));
        let inner = RootScope::<Bot>::new(Emitter::default(), 0);
        let mut child = ChildScope::new(inner, flag);

        let mut grandchild = child.sub();
        grandchild.close();
    }

    #[test]
    fn as_trait_object_close_delegates_correctly() {
        let flag = Arc::new(AtomicBool::new(false));
        let inner = RootScope::<Bot>::new(Emitter::default(), 0);
        let mut scope: Box<dyn SubScope> = Box::new(ChildScope::new(inner, Arc::clone(&flag)));
        scope.close();
        assert!(!flag.load(Ordering::SeqCst));
    }
}
