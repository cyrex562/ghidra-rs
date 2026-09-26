//! A generator for choosing method names to invoke for memory access.
//!
//! Port of `ghidra.pcode.emu.jit.gen.access.MethodAccessGen`.

/// A generator whose implementation is to emit invocations of a named method in
/// `JitCompiledPassage`.
///
/// This trait is needed by `LoadOpGen` and `StoreOpGen`.
///
/// Port of `ghidra.pcode.emu.jit.gen.access.MethodAccessGen`.
pub trait MethodAccessGen: Send + Sync {
    /// Choose the name of the read method, e.g. `JitCompiledPassage::readInt1(byte[], int)`, to
    /// use for the given variable size.
    ///
    /// # Arguments
    ///
    /// * `size` - the size in bytes
    ///
    /// Port of `MethodAccessGen.chooseReadName`.
    fn choose_read_name(&self, size: i32) -> String;

    /// Choose the name of the write method, e.g.
    /// `JitCompiledPassage::writeInt1(int, byte[], int)`, to use for the given variable size.
    ///
    /// # Arguments
    ///
    /// * `size` - the size in bytes
    ///
    /// Port of `MethodAccessGen.chooseWriteName`.
    fn choose_write_name(&self, size: i32) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestImpl;
    impl MethodAccessGen for TestImpl {
        fn choose_read_name(&self, size: i32) -> String {
            format!("read{}", size)
        }

        fn choose_write_name(&self, size: i32) -> String {
            format!("write{}", size)
        }
    }

    #[test]
    fn method_access_gen_trait_is_object_safe() {
        let impl_obj = TestImpl;
        let _trait_obj: &dyn MethodAccessGen = &impl_obj;
        assert_eq!(impl_obj.choose_read_name(1), "read1");
        assert_eq!(impl_obj.choose_write_name(2), "write2");
    }
}
