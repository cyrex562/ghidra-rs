use crate::format::seam_stubs::{MarkupSession, StructureContext};

/// A function that decorates a Ghidra structure.
///
/// This is the Rust equivalent of the Java `StructureMarkupFunction<T>` functional interface
/// from `ghidra.app.util.bin.format.golang.structmapping`.
///
/// In Java the interface declares a single method:
/// ```java
/// void markupStructure(StructureContext<T> context, MarkupSession markupSession)
///     throws IOException, CancelledException;
/// ```
/// In Rust this is expressed as a trait with a generic type parameter.
pub trait StructureMarkupFunction<T> {
    /// Decorates the specified structure.
    ///
    /// # Arguments
    ///
    /// * `context` - information about the structure being decorated
    /// * `markup_session` - state and methods to assist marking up the program
    ///
    /// # Errors
    ///
    /// Returns an error if the markup operation fails or is cancelled.
    fn markup_structure(&self, context: &dyn StructureContext<T>, markup_session: &dyn MarkupSession) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    struct TestType {
        value: i32,
    }

    struct MockStructureContext {
        test_value: i32,
    }

    impl StructureContext<TestType> for MockStructureContext {
        fn get_mapping_info(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_data_type_mapper(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_containing_field_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }

        fn get_structure_address(&self) -> crate::program::model::address::Address {
            unimplemented!()
        }

        fn get_field_address(&self, _field_offset: i64) -> crate::program::model::address::Address {
            unimplemented!()
        }

        fn get_field_location(&self, _field_offset: i64) -> i64 {
            0
        }

        fn get_structure_start(&self) -> i64 {
            0
        }

        fn get_structure_end(&self) -> i64 {
            1000
        }

        fn get_structure_length(&self) -> i32 {
            1000
        }

        fn get_structure_instance(&self) -> &TestType {
            unimplemented!()
        }

        fn get_reader(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_field_reader(&self, _field_offset: i64) -> Box<dyn Any> {
            unimplemented!()
        }

        fn create_field_context(&self, _fmi: &dyn Any, _include_reader: bool) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_structure_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::structure::Structure>> {
            unimplemented!()
        }

        fn to_string(&self) -> String {
            format!("MockStructureContext({})", self.test_value)
        }
    }

    struct MockMarkupSession {
        called: std::sync::Arc<std::sync::Mutex<bool>>,
    }

    impl MarkupSession for MockMarkupSession {
        fn get_program(&self) -> Box<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }

        fn get_mapping_context(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_markedup_addresses(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn markup(&self, _obj: &dyn Any, _nested: bool) -> std::io::Result<()> {
            *self.called.lock().unwrap() = true;
            Ok(())
        }

        fn markup_address(&self, _addr: crate::program::model::address::Address, _dt: &dyn Any) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_address_if_undefined(&self, _addr: crate::program::model::address::Address, _dt: &dyn Any) -> std::io::Result<()> {
            Ok(())
        }

        fn label_structure(&self, _obj: &dyn Any, _symbol_name: &str, _namespace_name: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn label_address(&self, _addr: crate::program::model::address::Address, _symbol_name: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn append_comment(
            &self,
            _field_context: &dyn Any,
            _comment_type: &dyn Any,
            _prefix: &str,
            _comment: &str,
            _sep: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_structure(&self, _structure_context: &dyn Any, _nested: bool) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_array_element_references(
            &self,
            _array_addr: crate::program::model::address::Address,
            _element_size: i32,
            _target_addrs: Vec<crate::program::model::address::Address>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn create_function_if_missing(
            &self,
            _name: &str,
            _ns: &dyn Any,
            _addr: crate::program::model::address::Address,
        ) -> Box<dyn Any> {
            unimplemented!()
        }

        fn add_reference(&self, _field_context: &dyn Any, _ref_dest: crate::program::model::address::Address) {
        }

        fn log_warning_at(&self, _addr: crate::program::model::address::Address, _msg: &str) {
        }
    }

    struct NoOpMarkupFunction;

    impl StructureMarkupFunction<TestType> for NoOpMarkupFunction {
        fn markup_structure(&self, _context: &dyn StructureContext<TestType>, _markup_session: &dyn MarkupSession) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn markup_function_no_op_succeeds() {
        let func = NoOpMarkupFunction;
        let ctx = MockStructureContext { test_value: 42 };
        let markup_session = MockMarkupSession { called: std::sync::Arc::new(std::sync::Mutex::new(false)) };

        let result = func.markup_structure(&ctx, &markup_session);
        assert!(result.is_ok());
    }

    struct FailingMarkupFunction;

    impl StructureMarkupFunction<TestType> for FailingMarkupFunction {
        fn markup_structure(&self, _context: &dyn StructureContext<TestType>, _markup_session: &dyn MarkupSession) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "markup failed"))
        }
    }

    #[test]
    fn markup_function_error_propagates() {
        let func = FailingMarkupFunction;
        let ctx = MockStructureContext { test_value: 42 };
        let markup_session = MockMarkupSession { called: std::sync::Arc::new(std::sync::Mutex::new(false)) };

        let result = func.markup_structure(&ctx, &markup_session);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("markup failed"));
    }

    struct CallMarkupFunction;

    impl StructureMarkupFunction<TestType> for CallMarkupFunction {
        fn markup_structure(&self, _context: &dyn StructureContext<TestType>, markup_session: &dyn MarkupSession) -> std::io::Result<()> {
            markup_session.markup(&0 as &dyn Any, false)?;
            Ok(())
        }
    }

    #[test]
    fn markup_function_calls_session_method() {
        let func = CallMarkupFunction;
        let ctx = MockStructureContext { test_value: 42 };
        let markup_session = MockMarkupSession { called: std::sync::Arc::new(std::sync::Mutex::new(false)) };

        let result = func.markup_structure(&ctx, &markup_session);
        assert!(result.is_ok());
        assert!(*markup_session.called.lock().unwrap());
    }
}
