//! A constant operand that can be pushed onto the JVM stack.
//!
//! Port of `ghidra.pcode.emu.jit.gen.opnd.ConstSimpleOpnd`.
//!
//! # Differences from Java
//!
//! - Java's `ConstSimpleOpnd<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>` carries both the
//!   JVM type `T` and the p-code type `JT`. `JT` is dropped here, matching the existing port of
//!   [`SimpleOpnd`](crate::pcode::emu::jit::gen::opnd::SimpleOpnd), for the same reasons as there.
//! - The `writeDirect` method throws `UnsupportedOperationException` in Java. Implementers are
//!   expected to override `write` instead, which generates a temporary variable to hold the result.

use crate::pcode::emu::jit::gen::opnd::simple_opnd::SimpleOpnd;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::BPrim;

/// A constant operand that can be pushed onto the JVM stack.
///
/// Port of `ghidra.pcode.emu.jit.gen.opnd.ConstSimpleOpnd<T, JT>`. See the [module docs](self)
/// for how this differs from the Java interface.
pub trait ConstSimpleOpnd<T: BPrim + 'static>: SimpleOpnd<T> + Send + Sync {
    /// Get the name of this constant operand.
    ///
    /// This is required to generate temporary variable names. Implementors should return a
    /// descriptive name for the constant value.
    fn name(&self) -> String;

    /// Generate a name for a temporary variable that might hold this constant.
    ///
    /// Port of `ConstSimpleOpnd.tempName()`. Returns a formatted string using the operand's
    /// name as a basis.
    fn temp_name(&self) -> String {
        format!("{}_tempFromRo", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::types::{TInt, T_INT};

    struct MockConstOpnd;

    impl SimpleOpnd<TInt> for MockConstOpnd {
        fn read<N: Next>(&self, em: Emitter<N>) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn write_direct<N1: Next>(&self, em: Emitter<Ent<N1, TInt>>) -> Emitter<N1> {
            em.recast()
        }
    }

    impl ConstSimpleOpnd<TInt> for MockConstOpnd {
        fn name(&self) -> String {
            "const_int_0x42".to_string()
        }
    }

    #[test]
    fn temp_name_formats_with_suffix() {
        let opnd = MockConstOpnd;
        let temp_name = opnd.temp_name();
        assert_eq!(temp_name, "const_int_0x42_tempFromRo");
    }

    #[test]
    fn temp_name_contains_original_name() {
        let opnd = MockConstOpnd;
        let temp_name = opnd.temp_name();
        assert!(temp_name.contains("const_int_0x42"));
        assert!(temp_name.contains("tempFromRo"));
    }
}
