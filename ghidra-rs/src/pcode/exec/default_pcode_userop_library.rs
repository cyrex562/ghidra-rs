//! The default implementation of a userop library.
//!
//! Corresponds to `ghidra.pcode.exec.DefaultPcodeUseropLibrary`.
//!
//! Userops are added by calling [`DefaultPcodeUseropLibrary::put_op`], usually in the constructor.

use std::sync::Arc;

use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary, UseropMap,
};

/// The default implementation of a userop library.
///
/// `T` is the type of data processed by the library.
pub struct DefaultPcodeUseropLibrary<T: 'static> {
    ops: UseropMap<T>,
}

impl<T: 'static> DefaultPcodeUseropLibrary<T> {
    /// Construct an empty userop library.
    pub fn new() -> Self {
        Self { ops: UseropMap::new() }
    }

    /// Add the given userop to this library.
    pub fn put_op(&mut self, userop: Arc<dyn PcodeUseropDefinition<T>>) {
        self.ops.insert(userop.get_name().to_string(), userop);
    }
}

impl<T: 'static> Default for DefaultPcodeUseropLibrary<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: 'static> ErasedPcodeUseropLibrary for DefaultPcodeUseropLibrary<T> {}

impl<T: 'static> PcodeUseropLibrary<T> for DefaultPcodeUseropLibrary<T> {
    fn get_userops(&self) -> &UseropMap<T> {
        &self.ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;

    /// A minimal userop definition for testing.
    struct TestUserop {
        name: String,
        input_count: i32,
    }

    impl TestUserop {
        fn new(name: &str, input_count: i32) -> Arc<Self> {
            Arc::new(Self { name: name.to_string(), input_count })
        }
    }

    impl PcodeUseropDefinition<i64> for TestUserop {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_input_count(&self) -> i32 {
            self.input_count
        }

        fn execute(
            &self,
            _executor: &crate::pcode::exec::pcode_executor::PcodeExecutor<i64>,
            _library: &dyn PcodeUseropLibrary<i64>,
            _op: &crate::program::model::pcode::PcodeOp,
            _out_var: Option<&crate::program::model::pcode::Varnode>,
            _in_vars: &[crate::program::model::pcode::Varnode],
        ) {
        }

        fn is_functional(&self) -> bool {
            true
        }

        fn has_side_effects(&self) -> bool {
            false
        }

        fn modifies_context(&self) -> bool {
            false
        }

        fn can_inline_pcode(&self) -> bool {
            false
        }

        fn get_output_type(&self) -> Option<TypeId> {
            None
        }

        fn get_java_method(&self) -> Option<()> {
            None
        }

        fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
            None
        }
    }

    #[test]
    fn new_library_is_empty() {
        let library: DefaultPcodeUseropLibrary<i64> = DefaultPcodeUseropLibrary::new();
        assert!(library.get_userops().is_empty());
    }

    #[test]
    fn put_op_adds_userop_to_library() {
        let mut library = DefaultPcodeUseropLibrary::new();
        let userop = TestUserop::new("test_op", 2);
        library.put_op(userop.clone());

        assert_eq!(library.get_userops().len(), 1);
        assert!(library.get_userops().contains_key("test_op"));
        assert_eq!(
            library.get_userops()["test_op"].get_input_count(),
            2
        );
    }

    #[test]
    fn multiple_userops_can_be_added() {
        let mut library = DefaultPcodeUseropLibrary::new();
        library.put_op(TestUserop::new("op1", 1));
        library.put_op(TestUserop::new("op2", 2));
        library.put_op(TestUserop::new("op3", 3));

        assert_eq!(library.get_userops().len(), 3);
        assert_eq!(library.get_userops()["op1"].get_input_count(), 1);
        assert_eq!(library.get_userops()["op2"].get_input_count(), 2);
        assert_eq!(library.get_userops()["op3"].get_input_count(), 3);
    }

    #[test]
    fn default_creates_empty_library() {
        let library: DefaultPcodeUseropLibrary<i64> = Default::default();
        assert!(library.get_userops().is_empty());
    }

    #[test]
    fn put_op_with_duplicate_name_overwrites() {
        let mut library = DefaultPcodeUseropLibrary::new();
        let userop1 = TestUserop::new("op", 1);
        let userop2 = TestUserop::new("op", 2);

        library.put_op(userop1);
        library.put_op(userop2);

        assert_eq!(library.get_userops().len(), 1);
        assert_eq!(library.get_userops()["op"].get_input_count(), 2);
    }
}
