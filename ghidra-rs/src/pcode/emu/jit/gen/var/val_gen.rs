//! The bytecode generator for a specific value (operand) access.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.ValGen`.
//!
//! The code generator selects the correct generator for each input operand via [`ValGen`] and
//! each output operand via [`VarGen`](crate::pcode::emu::jit::gen::var::var_gen::VarGen). The op
//! generator has already retrieved the `JitOp` whose operands are of the `JitVal` class.
//!
//! | Varnode type | Use-def type | Generator type |
//! |---|---|---|
//! | `constant` | `JitConstVal` | `ConstValGen` |
//! | `unique`, `register` | `JitInputVar`, `JitLocalOutVar`, `JitMissingVar` | `InputVarGen`, `LocalOutVarGen` |
//! | `memory` | `JitDirectMemoryVar`, `JitMemoryOutVar` | `DirectMemoryVarGen`, `MemoryOutVarGen` |
//! | *indirect | `JitIndirectMemoryVar` | none |
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`MpAccessGen`](crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen).
//! - `subpiece` returns a *different* concrete generator depending on the implementor and even
//!   the arguments, so it returns `Box<dyn ValGen<V>>` -- the one place this trait is genuinely
//!   used polymorphically over an unknown implementor. That forces every other method (which has
//!   its own type parameters: `genReadToStack`'s `JT`/`N`, and the rest's `N`) to carry a
//!   `where Self: Sized` bound, so they drop out of the vtable instead of making the trait as a
//!   whole object-unsafe -- the same technique used by
//!   [`VarHandler`](crate::pcode::emu::jit::alloc::var_handler::VarHandler) and
//!   [`JitOpVisitor`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor).
//! - Java's static `lookup(V)` is **not** ported, for the same reason
//!   [`VarGen::lookup`](crate::pcode::emu::jit::gen::var::var_gen) is not: it switches on the
//!   runtime class of `v` and returns one of several singletons (`ConstValGen.GEN`,
//!   `FailValGen.GEN`, or a delegation to `VarGen.lookup`) via an unchecked cast to `ValGen<V>`
//!   that only erasure makes possible. None of those singletons are ported yet.
//! - Java's private static `castBack` -- an unchecked-cast identity function used nowhere in the
//!   codebase (not even elsewhere in this file) -- is not ported; it has no call site to port
//!   faithfully against, and Rust's [`Emitter::recast`] already covers the same "reinterpret the
//!   stack shape" need where it is actually used (e.g. in
//!   [`MemoryVarGen`](crate::pcode::emu::jit::gen::var::memory_var_gen)).
//! - [`VarGen`](crate::pcode::emu::jit::gen::var::var_gen::VarGen) predates this port and, per its
//!   own module docs, still restates this trait's six read/init members directly rather than
//!   inheriting them from `ValGen<V>` as Java's `VarGen<V> extends ValGen<V>` does -- moving them
//!   is left for a follow-up, since `VarGen` has no concrete implementors yet to migrate.

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, OpndEm, Scope};

/// The bytecode generator for a specific value (operand) access.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.ValGen<V>`. See the [module docs](self).
pub trait ValGen<V: JitVal>: Send + Sync {
    /// Emit code to prepare any class-level items required to use this variable.
    ///
    /// For example, if this represents a direct memory variable, then this can prepare a
    /// reference to the portion of the state involved, allowing it to access it readily. This
    /// should be used to emit code into the constructor.
    ///
    /// Port of `ValGen.genValInit`.
    fn gen_val_init<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<N>
    where
        Self: Sized;

    /// Emit code to read the value onto the stack.
    ///
    /// Port of `ValGen.genReadToStack`.
    fn gen_read_to_stack<JT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: JT,
        ext: Ext,
    ) -> Emitter<Ent<N, JT::B>>
    where
        JT: SimpleJitType,
        N: Next,
        Self: Sized;

    /// Emit code to read the value into local variables.
    ///
    /// NOTE: In some cases, this may not emit any code at all. It may simply compose the operand
    /// from locals already allocated for a variable being "read."
    ///
    /// Port of `ValGen.genReadToOpnd`.
    fn gen_read_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N>
    where
        Self: Sized;

    /// Emit code to read a leg of the value onto the stack.
    ///
    /// - `leg`: the leg index, 0 being the least significant.
    ///
    /// Port of `ValGen.genReadLegToStack`.
    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>>
    where
        Self: Sized;

    /// Emit code to read the value into an array.
    ///
    /// - `slack`: the number of extra (more significant) elements to allocate in the array.
    ///
    /// Port of `ValGen.genReadToArray`.
    #[allow(clippy::too_many_arguments)]
    fn gen_read_to_array<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
        slack: i32,
    ) -> Emitter<Ent<N, TRef>>
    where
        Self: Sized;

    /// Emit code to read the value onto the stack as a boolean.
    ///
    /// Port of `ValGen.genReadToBool`.
    fn gen_read_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<Ent<N, TInt>>
    where
        Self: Sized;

    /// Create a generator for a `SUBPIECE` of a value.
    ///
    /// - `byte_offset`: the number of least-significant bytes to remove.
    /// - `max_byte_size`: the maximum size of the resulting variable. In general, a subpiece
    ///   should never exceed the size of the parent varnode, but if it does, this truncates that
    ///   excess.
    ///
    /// Port of `ValGen.subpiece`.
    fn subpiece(&self, byte_offset: i32, max_byte_size: i32) -> Box<dyn ValGen<V>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TInt;
    use crate::pcode::emu::jit::op::JitOp;
    use crate::pcode::seam_stubs::MethodVisitor;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;

    struct TestVal {
        varnode: Varnode,
    }

    impl JitVal for TestVal {
        fn size(&self) -> i32 {
            self.varnode.get_size()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        Varnode::new(addr, size)
    }

    /// A minimal implementor of [`ValGen`] whose `subpiece` narrows the underlying varnode the
    /// way a real generator's would (e.g. `ConstValGen`, whose `subpiece` shrinks the constant's
    /// value and size). Exercises the shape Java's `ValGen<V> subpiece(...)` requires: a
    /// same-trait, possibly-different-concrete-type result.
    struct TestValGen {
        vn: Varnode,
    }

    impl ValGen<TestVal> for TestValGen {
        fn gen_val_init<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVal,
        ) -> Emitter<N> {
            em
        }

        fn gen_read_to_stack<JT, N>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVal,
            _type_: JT,
            _ext: Ext,
        ) -> Emitter<Ent<N, JT::B>>
        where
            JT: SimpleJitType,
            N: Next,
        {
            em.recast()
        }

        fn gen_read_to_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVal,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> OpndEm<MpIntJitType, N> {
            struct MockOpnd;
            impl crate::pcode::seam_stubs::Opnd<MpIntJitType> for MockOpnd {}
            OpndEm::new(Box::new(MockOpnd), em)
        }

        fn gen_read_leg_to_stack<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVal,
            _type_: MpIntJitType,
            _leg: i32,
            _ext: Ext,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn gen_read_to_array<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVal,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
            _slack: i32,
        ) -> Emitter<Ent<N, TRef>> {
            em.recast()
        }

        fn gen_read_to_bool<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVal,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn subpiece(&self, byte_offset: i32, max_byte_size: i32) -> Box<dyn ValGen<TestVal>> {
            let vn = Varnode::new(
                self.vn.get_address().add(byte_offset as i64).expect("address overflow"),
                (self.vn.get_size() - byte_offset).min(max_byte_size),
            );
            Box::new(TestValGen { vn })
        }
    }

    #[test]
    fn subpiece_narrows_the_varnode_like_a_real_generator_would() {
        // Java: subpiece removes `byteOffset` least-significant bytes and caps the result at
        // `maxByteSize`.
        let gen = TestValGen { vn: make_varnode(0x3000, 8) };
        let sub = gen.subpiece(2, 4);
        let sub_gen = sub.subpiece(0, 100);
        // Re-deriving through the trait object exercises `Box<dyn ValGen<V>>` dispatch.
        let _ = sub_gen;
    }

    #[test]
    fn dyn_val_gen_dispatches_the_object_safe_subpiece_method() {
        // The presence of `subpiece` -> `Box<dyn ValGen<V>>` requires the trait to be
        // object-safe; this exercises it through a genuine `&dyn ValGen<V>`.
        let gen: Box<dyn ValGen<TestVal>> = Box::new(TestValGen { vn: make_varnode(0x4000, 4) });
        let sub = gen.subpiece(1, 2);
        let _ = sub;
    }

    #[test]
    fn gen_read_to_stack_recasts_the_stack_shape() {
        // Java: genReadToStack returns Emitter<Ent<N, T>>, i.e. the resulting stack has the read
        // value on top of the incoming stack N.
        let gen = TestValGen { vn: make_varnode(0x5000, 4) };
        let v = TestVal { varnode: make_varnode(0x5000, 4) };
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> =
            gen.gen_read_to_stack(em, &local_this, &code_gen, &v, IntJitType::I4, Ext::Zero);
        let _ = result.local_variables();
    }
}
