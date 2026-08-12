//! An access generator for simple-typed variables.
//!
//! Port of `ghidra.pcode.emu.jit.gen.access.SimpleAccessGen`.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by [`MpAccessGen`](crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen).
//! - The recursive self type parameter (`JT extends SimpleJitType<T, JT>`) is dropped, matching the
//!   port of [`SimpleJitType`](crate::pcode::emu::jit::analysis::jit_type::SimpleJitType).

use crate::pcode::emu::jit::analysis::jit_type::SimpleJitType;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{BPrim, TRef};
use crate::pcode::seam_stubs::{AccessGen, JitCodeGenerator};
use crate::program::model::pcode::Varnode;

/// An access generator for simple-typed variables.
///
/// Port of `ghidra.pcode.emu.jit.gen.access.SimpleAccessGen`.
pub trait SimpleAccessGen<T, JT>: AccessGen<JT>
where
    T: BPrim,
    JT: SimpleJitType<B = T>,
{
    /// Emit bytecode to load a varnode's value onto the JVM stack.
    ///
    /// Port of `SimpleAccessGen.genReadToStack`.
    ///
    /// If the varnode fits completely in one block (the common case), this accesses the bytes
    /// from that block using the method chosen by size. If the varnode extends into the next
    /// block, this will split the varnode into two portions according to machine byte order.
    /// Each portion is accessed using the method for the size of that portion. The results are
    /// reassembled into a single value.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `vn`: the varnode.
    ///
    /// # Returns
    ///
    /// The emitter with the resulting stack, i.e., having pushed the value onto it.
    fn gen_read_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
    ) -> Emitter<Ent<N, T>>;

    /// Emit bytecode to store a value into a varnode from the JVM stack.
    ///
    /// Port of `SimpleAccessGen.genWriteFromStack`.
    ///
    /// If the varnode fits completely in one block (the common case), this accesses the bytes
    /// from that block using the method chosen by size. If the varnode extends into the next
    /// block, this will split the varnode into two portions according to machine byte order.
    /// Each portion is accessed using the method for the size of that portion.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack, having the value on top.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `vn`: the varnode.
    ///
    /// # Returns
    ///
    /// The emitter with the resulting stack, i.e., having popped the value.
    fn gen_write_from_stack<N1: Next>(
        &self,
        em: Emitter<Ent<N1, T>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
    ) -> Emitter<N1>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TInt;
    use crate::pcode::seam_stubs::MethodVisitor;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    /// A minimal implementor exercising the type-level plumbing (stack shapes, `this`/generator
    /// pass-through) without any real bytecode-generation logic.
    struct TestSimpleAccessGen;

    impl AccessGen<IntJitType> for TestSimpleAccessGen {}

    impl SimpleAccessGen<TInt, IntJitType> for TestSimpleAccessGen {
        fn gen_read_to_stack<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _vn: &Varnode,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn gen_write_from_stack<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TInt>>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _vn: &Varnode,
        ) -> Emitter<N1> {
            em.recast()
        }
    }

    fn make_varnode() -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        Varnode::new(addr, 4)
    }

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    #[test]
    fn gen_read_to_stack_pushes_value_onto_stack() {
        let gen_impl = TestSimpleAccessGen;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode();

        // Java: genReadToStack returns Emitter<Ent<N, T>>, i.e., the resulting stack
        // has the value on top of the incoming stack N.
        let result: Emitter<Ent<Bot, TInt>> =
            gen_impl.gen_read_to_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_from_stack_pops_value_off_stack() {
        let gen_impl = TestSimpleAccessGen;
        let em: Emitter<Ent<Bot, TInt>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let vn = make_varnode();

        // Java: genWriteFromStack consumes the value (N0 = Ent<N1, T>) and returns
        // Emitter<N1>, i.e., the stack beneath it.
        let result: Emitter<Bot> =
            gen_impl.gen_write_from_stack(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn simple_access_gen_extends_access_gen() {
        let gen_impl = TestSimpleAccessGen;
        let _as_access_gen: &dyn AccessGen<IntJitType> = &gen_impl;
    }
}
