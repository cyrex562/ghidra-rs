//! The generator for a subpiece of a local variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.SubLocalVarGen`.

use crate::pcode::emu::jit::gen::var::local_var_gen::LocalVarGen;
use crate::pcode::emu::jit::var::JitVarnodeVar;
use crate::pcode::seam_stubs::JitCodeGenerator;

/// The generator for a subpiece of a local variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.SubLocalVarGen<V>`. See the [module docs](self).
///
/// # Differences from Java
///
/// - Java's `SubLocalVarGen` declares a `subpiece` method that throws, but since it is never
///   called in practice and creates a trait object compatibility issue in Rust, it is omitted here
///   (following the pattern of `SubMemoryVarGen`).
pub trait SubLocalVarGen<V: JitVarnodeVar>: LocalVarGen<V> {
    /// Return the number of bytes to the right of the subpiece.
    fn byte_offset(&self) -> i32;

    /// Return the size of the subpiece.
    fn max_byte_size(&self) -> i32;

    /// Port of `SubLocalVarGen.getHandler`.
    fn get_handler(&self, gen: &dyn JitCodeGenerator, v: &V) -> Box<dyn crate::pcode::emu::jit::alloc::var_handler::VarHandler> {
        LocalVarGen::get_handler(self, gen, v).subpiece(
            gen.get_analysis_context().get_endian(),
            self.byte_offset(),
            self.max_byte_size(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::var::JitDirectMemoryVar;
    use crate::pcode::seam_stubs::VarGen;

    struct TestSubLocalVarGen {
        byte_offset: i32,
        max_byte_size: i32,
    }

    impl LocalVarGen<JitDirectMemoryVar> for TestSubLocalVarGen {}

    impl SubLocalVarGen<JitDirectMemoryVar> for TestSubLocalVarGen {
        fn byte_offset(&self) -> i32 {
            self.byte_offset
        }

        fn max_byte_size(&self) -> i32 {
            self.max_byte_size
        }
    }

    impl VarGen<JitDirectMemoryVar> for TestSubLocalVarGen {
        fn gen_val_init<N: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<N> {
            em
        }

        fn gen_read_to_stack<
            JT: crate::pcode::emu::jit::analysis::jit_type::SimpleJitType,
            N: crate::pcode::emu::jit::gen::util::emitter::Next,
        >(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
            _type_: JT,
            _ext: crate::pcode::seam_stubs::Ext,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<crate::pcode::emu::jit::gen::util::emitter::Ent<N, JT::B>> {
            em.recast()
        }

        fn gen_read_to_opnd<N: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            _em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
            _type_: crate::pcode::emu::jit::analysis::jit_type::MpIntJitType,
            _ext: crate::pcode::seam_stubs::Ext,
            _scope: &dyn crate::pcode::seam_stubs::Scope,
        ) -> crate::pcode::seam_stubs::OpndEm<crate::pcode::emu::jit::analysis::jit_type::MpIntJitType, N> {
            panic!("Test stub")
        }

        fn gen_read_leg_to_stack<N: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
            _type_: crate::pcode::emu::jit::analysis::jit_type::MpIntJitType,
            _leg: i32,
            _ext: crate::pcode::seam_stubs::Ext,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<crate::pcode::emu::jit::gen::util::emitter::Ent<N, crate::pcode::emu::jit::gen::util::types::TInt>> {
            em.recast()
        }

        fn gen_read_to_array<N: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
            _type_: crate::pcode::emu::jit::analysis::jit_type::MpIntJitType,
            _ext: crate::pcode::seam_stubs::Ext,
            _scope: &dyn crate::pcode::seam_stubs::Scope,
            _slack: i32,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<crate::pcode::emu::jit::gen::util::emitter::Ent<N, crate::pcode::emu::jit::gen::util::types::TRef>> {
            em.recast()
        }

        fn gen_read_to_bool<N: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<crate::pcode::emu::jit::gen::util::emitter::Ent<N, crate::pcode::emu::jit::gen::util::types::TInt>> {
            em.recast()
        }

        fn gen_write_from_stack<
            JT: crate::pcode::emu::jit::analysis::jit_type::SimpleJitType,
            N1: crate::pcode::emu::jit::gen::util::emitter::Next,
        >(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<crate::pcode::emu::jit::gen::util::emitter::Ent<N1, JT::B>>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
            _type_: JT,
            _ext: crate::pcode::seam_stubs::Ext,
            _scope: &dyn crate::pcode::seam_stubs::Scope,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<N1> {
            em.recast()
        }

        fn gen_write_from_opnd<N: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
            _opnd: &dyn crate::pcode::seam_stubs::Opnd<crate::pcode::emu::jit::analysis::jit_type::MpIntJitType>,
            _ext: crate::pcode::seam_stubs::Ext,
            _scope: &dyn crate::pcode::seam_stubs::Scope,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<N> {
            em
        }

        fn gen_write_from_array<N1: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<crate::pcode::emu::jit::gen::util::emitter::Ent<N1, crate::pcode::emu::jit::gen::util::types::TRef>>,
            _local_this: &crate::pcode::emu::jit::gen::util::local::Local<crate::pcode::emu::jit::gen::util::types::TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &JitDirectMemoryVar,
            _type_: crate::pcode::emu::jit::analysis::jit_type::MpIntJitType,
            _ext: crate::pcode::seam_stubs::Ext,
            _scope: &dyn crate::pcode::seam_stubs::Scope,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<N1> {
            em.recast()
        }
    }

    #[test]
    fn byte_offset_and_max_byte_size_are_stored() {
        let gen_impl = TestSubLocalVarGen {
            byte_offset: 2,
            max_byte_size: 4,
        };

        assert_eq!(gen_impl.byte_offset(), 2);
        assert_eq!(gen_impl.max_byte_size(), 4);
    }
}
