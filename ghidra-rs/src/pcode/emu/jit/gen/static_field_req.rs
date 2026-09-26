/// A static field request initialized in the class initializer.
///
/// Corresponds to `ghidra.pcode.emu.jit.gen.StaticFieldReq`.
///
/// This trait extends [`FieldReq`] with two methods for emitting field initialization and load code.
/// Both methods are generic over the stack state type (which must implement [`Next`]).
///
/// # Type Parameters
///
/// - `T`: The JVM type of the field, implementing [`BNonVoid`].
///
/// [`FieldReq`]: super::field_req::FieldReq
/// [`Next`]: crate::pcode::emu::jit::gen::util::emitter::Next
/// [`BNonVoid`]: crate::pcode::emu::jit::gen::util::types::BNonVoid

use crate::pcode::emu::jit::gen::field_req::FieldReq;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::BNonVoid;
use crate::pcode::seam_stubs::{ClassVisitor, JitCodeGenerator};

pub trait StaticFieldReq<T: BNonVoid>: FieldReq<T> {
    /// Emit the field declaration and its initialization bytecode.
    ///
    /// The declaration is emitted into the class definition, and the initialization code is
    /// emitted into the class initializer.
    ///
    /// # Type Parameters
    ///
    /// - `N`: The incoming stack state, implementing [`Next`].
    ///
    /// # Arguments
    ///
    /// - `em`: The emitter typed with the incoming stack.
    /// - `gen`: The code generator.
    /// - `cv`: The visitor for the class definition.
    ///
    /// # Returns
    ///
    /// The emitter typed with the incoming stack.
    fn gen_cl_init_code<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        cv: &ClassVisitor,
    ) -> Emitter<N>;

    /// Emit code to load the field onto the JVM stack.
    ///
    /// # Type Parameters
    ///
    /// - `N`: The incoming stack state, implementing [`Next`].
    ///
    /// # Arguments
    ///
    /// - `em`: The emitter typed with the incoming stack.
    /// - `gen`: The code generator.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., having pushed the value.
    fn gen_load<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
    ) -> Emitter<Ent<N, T>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::types::TInt;

    struct TestField {
        field_name: String,
    }

    impl FieldReq<TInt> for TestField {
        fn name(&self) -> String {
            self.field_name.clone()
        }
    }

    impl StaticFieldReq<TInt> for TestField {
        fn gen_cl_init_code<N: Next>(
            &self,
            em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _cv: &ClassVisitor,
        ) -> Emitter<N> {
            em
        }

        fn gen_load<N: Next>(
            &self,
            em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }
    }

    #[test]
    fn static_field_req_name() {
        let field = TestField {
            field_name: "myStaticField".to_string(),
        };
        assert_eq!(field.name(), "myStaticField");
    }

    #[test]
    fn static_field_req_extends_field_req() {
        let field = TestField {
            field_name: "testField".to_string(),
        };
        let _req: &dyn FieldReq<TInt> = &field;
    }
}
