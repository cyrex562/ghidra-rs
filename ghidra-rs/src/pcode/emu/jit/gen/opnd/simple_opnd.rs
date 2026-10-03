//! An operand stored in a single JVM local variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd`.
//!
//! # Differences from Java
//!
//! - Java's `SimpleOpnd<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>` carries both the
//!   JVM type `T` and the p-code type `JT`. `JT` is dropped here, matching the existing port of
//!   [`LocalOpnd`](crate::pcode::emu::jit::gen::opnd::LocalOpnd): nothing this trait's own members
//!   need depends on the p-code type, only on the JVM type `T`.
//! - The static factories `SimpleOpnd.of(JT, Local<T>)` and
//!   `SimpleOpnd.ofIntReadOnly(IntJitType, Local<TInt>)` are not ported. Both dispatch on the
//!   p-code type (`JitType.SimpleJitType` and its variants `IntJitType`/`LongJitType`/etc.) to one
//!   of `IntLocalOpnd`/`LongLocalOpnd`/`FloatLocalOpnd`/`DoubleLocalOpnd`/`IntReadOnlyLocalOpnd`'s
//!   own `of` constructors -- none of which are ported yet, and neither is the p-code type
//!   hierarchy they switch on. Add these once those land.
//! - `SimpleOpndEm.castBack` is an unchecked-cast workaround for Java's inability to prove two
//!   parameterizations of the same generic interface are equal after a `switch` over sealed
//!   subtypes of `JT`. Since `JT` is not carried here, there is nothing to cast between, so it is
//!   omitted.

use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::BPrim;
use crate::pcode::seam_stubs::Scope;

/// An operand-emitter tuple: an operand paired with the emitter after writing it.
///
/// Port of `SimpleOpnd.SimpleOpndEm<T, JT, N>`. The `JT` (p-code type) parameter is dropped, as
/// in [`SimpleOpnd`] itself; `O` is the concrete operand type in its place.
pub struct SimpleOpndEm<O, N> {
    /// The operand -- the same operand `write` was called on, unless overridden to substitute a
    /// newly generated one (as `ConstSimpleOpnd.writeDirect` does by throwing, forcing such
    /// implementors to override `write` itself).
    pub opnd: O,
    /// The emitter with the write's bytecode emitted.
    pub em: Emitter<N>,
}

/// An operand stored in a single JVM local variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd<T, JT>`. See the [module docs](self) for how
/// this differs from the Java interface.
pub trait SimpleOpnd<T: BPrim + 'static>: Send + Sync {
    /// Emit code to read the operand onto the stack.
    ///
    /// Port of `SimpleOpnd.read(Emitter<N>)`.
    fn read<N: Next>(&self, em: Emitter<N>) -> Emitter<Ent<N, T>>;

    /// Emit code to write the operand from the stack.
    ///
    /// This will generate a new operand if this operand is read-only. Callers must therefore be
    /// prepared to take the result in place of this operand.
    ///
    /// Port of `SimpleOpnd.write(Emitter<N0>, Scope)`. The default, as in Java, ignores `scope`
    /// and simply pairs this operand with the result of [`write_direct`](Self::write_direct);
    /// only implementors that must substitute a new operand (e.g., a read-only operand) need it,
    /// and so must override this method rather than just `write_direct`.
    fn write<N1: Next>(&self, em: Emitter<Ent<N1, T>>, scope: &dyn Scope) -> SimpleOpndEm<Self, N1>
    where
        Self: Sized + Clone,
    {
        let _ = scope;
        let em = self.write_direct(em);
        SimpleOpndEm { opnd: self.clone(), em }
    }

    /// Emit code to write the operand, without generating a new operand.
    ///
    /// This will throw an exception during generation if this operand is read-only. This should
    /// only be used when the caller is certain the operand can be written and when a scope is not
    /// available.
    ///
    /// Port of `SimpleOpnd.writeDirect(Emitter<N0>)`.
    fn write_direct<N1: Next>(&self, em: Emitter<Ent<N1, T>>) -> Emitter<N1>;

    /// The legs of this operand, in little-endian order.
    ///
    /// For non-legged types -- which is every [`SimpleOpnd`] -- this is the singleton list
    /// containing only this operand.
    ///
    /// Port of `SimpleOpnd.legsLE()`.
    fn legs_le(&self) -> Vec<&Self>
    where
        Self: Sized,
    {
        vec![self]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::{start, Bot};
    use crate::pcode::emu::jit::gen::util::local::Local;
    use crate::pcode::emu::jit::gen::util::types::{TInt, T_INT};
    use crate::pcode::seam_stubs::MethodVisitor;

    #[derive(Clone)]
    struct MockSimpleOpnd {
        local: Local<TInt>,
    }

    impl SimpleOpnd<TInt> for MockSimpleOpnd {
        fn read<N: Next>(&self, em: Emitter<N>) -> Emitter<Ent<N, TInt>> {
            // Real implementors (e.g. LocalOpnd) would emit `iload <local>` here; without `Op`
            // ported yet, just witness the stack-shape change.
            em.recast()
        }

        fn write_direct<N1: Next>(&self, em: Emitter<Ent<N1, TInt>>) -> Emitter<N1> {
            // Real implementors would emit `istore <local>` here.
            em.recast()
        }
    }

    struct MockScope;
    impl Scope for MockScope {}

    #[test]
    fn write_direct_changes_only_the_stack_shape() {
        let opnd = MockSimpleOpnd { local: Local::of(T_INT, "v", 0) };
        let em: Emitter<Ent<Bot, TInt>> = start(MethodVisitor::new()).recast();
        let _after: Emitter<Bot> = opnd.write_direct(em);
    }

    #[test]
    fn write_pairs_this_operand_with_write_directs_result() {
        // Java: `write` defaults to `new SimpleOpndEm<>(this, writeDirect(em))`.
        let opnd = MockSimpleOpnd { local: Local::of(T_INT, "v", 0) };
        let em: Emitter<Ent<Bot, TInt>> = start(MethodVisitor::new()).recast();
        let result = opnd.write(em, &MockScope);
        assert_eq!(result.opnd.local.name, "v");
    }

    #[test]
    fn legs_le_is_the_singleton_list_of_this_operand() {
        // Java: `legsLE()` defaults to `List.of(this)`.
        let opnd = MockSimpleOpnd { local: Local::of(T_INT, "v", 0) };
        let legs = opnd.legs_le();
        assert_eq!(legs.len(), 1);
        assert!(std::ptr::eq(legs[0], &opnd));
    }

    #[test]
    fn read_then_write_direct_round_trips_the_stack_shape() {
        let opnd = MockSimpleOpnd { local: Local::of(T_INT, "v", 0) };
        let em: Emitter<Bot> = start(MethodVisitor::new());
        let pushed: Emitter<Ent<Bot, TInt>> = opnd.read(em);
        let _popped: Emitter<Bot> = opnd.write_direct(pushed);
    }
}
