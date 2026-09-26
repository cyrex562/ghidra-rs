//! A mutable operand that can be contained in a single JVM local variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.opnd.LocalOpnd`.
//!
//! This trait represents an operand whose value is stored in a single JVM local variable.
//! It provides a handle to that local and a method to retrieve its name.

use crate::pcode::emu::jit::gen::opnd::simple_opnd::SimpleOpnd;
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::BPrim;

/// A mutable operand that can be contained in a single JVM local variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.opnd.LocalOpnd<T, JT>`. Represents an operand whose value
/// is stored in a single JVM local variable, with `T` being the JVM type and `JT` being the
/// p-code type.
///
/// # Type Parameters
///
/// - `T`: The JVM type (`BPrim`-bounded).
/// - `JT`: The p-code type (`SimpleJitType`-bounded, but generically represented here).
pub trait LocalOpnd<T: BPrim + 'static>: SimpleOpnd<T> {
    /// Get the local variable handle for this operand.
    ///
    /// Port of `LocalOpnd.local()`.
    fn local(&self) -> &Local<T>;

    /// Get the name of the local variable.
    ///
    /// Port of `LocalOpnd.name()`, which delegates to `local().name()`.
    fn name(&self) -> &str {
        self.local().name.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::types::T_INT;

    struct MockLocalOpnd {
        local: Local<crate::pcode::emu::jit::gen::util::types::TInt>,
    }

    impl SimpleOpnd<crate::pcode::emu::jit::gen::util::types::TInt> for MockLocalOpnd {
        fn read<N: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<N>,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<
            crate::pcode::emu::jit::gen::util::emitter::Ent<
                N,
                crate::pcode::emu::jit::gen::util::types::TInt,
            >,
        > {
            em.recast()
        }

        fn write_direct<N1: crate::pcode::emu::jit::gen::util::emitter::Next>(
            &self,
            em: crate::pcode::emu::jit::gen::util::emitter::Emitter<
                crate::pcode::emu::jit::gen::util::emitter::Ent<
                    N1,
                    crate::pcode::emu::jit::gen::util::types::TInt,
                >,
            >,
        ) -> crate::pcode::emu::jit::gen::util::emitter::Emitter<N1> {
            em.recast()
        }
    }

    impl LocalOpnd<crate::pcode::emu::jit::gen::util::types::TInt> for MockLocalOpnd {
        fn local(&self) -> &Local<crate::pcode::emu::jit::gen::util::types::TInt> {
            &self.local
        }
    }

    #[test]
    fn local_opnd_name_delegates_to_local() {
        let local = Local::of(T_INT, "test_var", 0);
        let opnd = MockLocalOpnd { local };
        assert_eq!(opnd.name(), "test_var");
    }

    #[test]
    fn local_opnd_returns_local_handle() {
        let local = Local::of(T_INT, "counter", 5);
        let opnd = MockLocalOpnd { local: local.clone() };
        assert_eq!(opnd.local().name, "counter");
        assert_eq!(opnd.local().index, 5);
    }

    #[test]
    fn local_opnd_with_different_names() {
        let local1 = Local::of(T_INT, "x", 0);
        let local2 = Local::of(T_INT, "y", 1);
        let opnd1 = MockLocalOpnd { local: local1 };
        let opnd2 = MockLocalOpnd { local: local2 };
        assert_ne!(opnd1.name(), opnd2.name());
        assert_eq!(opnd1.name(), "x");
        assert_eq!(opnd2.name(), "y");
    }
}
