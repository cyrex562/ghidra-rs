use crate::format::seam_stubs::{FieldContext, MarkupSession};
use crate::program::model::address::Address;

/// A function that decorates a field in a structure mapped class.
///
/// This is the Rust equivalent of the Java `FieldMarkupFunction<T>` functional interface
/// from `ghidra.app.util.bin.format.golang.structmapping`.
///
/// In Java the interface declares a single method:
/// ```java
/// void markupField(FieldContext<T> fieldContext, MarkupSession markupSession)
///     throws IOException, CancelledException;
/// ```
/// In Rust this is expressed as a trait with a generic type parameter.
pub trait FieldMarkupFunction<T> {
    /// Decorates the specified field.
    ///
    /// # Arguments
    ///
    /// * `field_context` - information about the field being decorated
    /// * `markup_session` - state and methods to assist marking up the program
    ///
    /// # Errors
    ///
    /// Returns an error if the markup operation fails or is cancelled.
    fn markup_field(&self, field_context: &dyn FieldContext<T>, markup_session: &dyn MarkupSession) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::{FieldContext, MarkupSession};
    use std::any::Any;

    struct TestType {
        value: i32,
    }

    struct MockFieldContext {
        test_value: i32,
    }

    impl FieldContext<TestType> for MockFieldContext {
        fn get_structure_instance(&self) -> &TestType {
            unimplemented!()
        }

        fn get_address(&self) -> Address {
            unimplemented!()
        }

        fn get_value(&self, _expected_type: &dyn Any) -> std::io::Result<Box<dyn Any>> {
            Ok(Box::new(self.test_value))
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

        fn markup_address(&self, _addr: Address, _dt: &dyn Any) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_address_if_undefined(&self, _addr: Address, _dt: &dyn Any) -> std::io::Result<()> {
            Ok(())
        }

        fn label_structure(&self, _obj: &dyn Any, _symbol_name: &str, _namespace_name: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn label_address(&self, _addr: Address, _symbol_name: &str) -> std::io::Result<()> {
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
            _array_addr: Address,
            _element_size: i32,
            _target_addrs: Vec<Address>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn create_function_if_missing(
            &self,
            _name: &str,
            _ns: &dyn Any,
            _addr: Address,
        ) -> Box<dyn Any> {
            unimplemented!()
        }

        fn add_reference(&self, _field_context: &dyn Any, _ref_dest: Address) {
        }

        fn log_warning_at(&self, _addr: Address, _msg: &str) {
        }
    }

    struct NoOpMarkupFunction;

    impl FieldMarkupFunction<TestType> for NoOpMarkupFunction {
        fn markup_field(&self, _field_context: &dyn FieldContext<TestType>, _markup_session: &dyn MarkupSession) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[test]
    fn markup_function_no_op_succeeds() {
        let func = NoOpMarkupFunction;
        let field_ctx = MockFieldContext { test_value: 42 };
        let markup_session = MockMarkupSession { called: std::sync::Arc::new(std::sync::Mutex::new(false)) };

        let result = func.markup_field(&field_ctx, &markup_session);
        assert!(result.is_ok());
    }

    struct FailingMarkupFunction;

    impl FieldMarkupFunction<TestType> for FailingMarkupFunction {
        fn markup_field(&self, _field_context: &dyn FieldContext<TestType>, _markup_session: &dyn MarkupSession) -> Result<(), Box<dyn std::error::Error>> {
            Err("markup failed".into())
        }
    }

    #[test]
    fn markup_function_error_propagates() {
        let func = FailingMarkupFunction;
        let field_ctx = MockFieldContext { test_value: 42 };
        let markup_session = MockMarkupSession { called: std::sync::Arc::new(std::sync::Mutex::new(false)) };

        let result = func.markup_field(&field_ctx, &markup_session);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("markup failed"));
    }

    struct CallMarkupFunction;

    impl FieldMarkupFunction<TestType> for CallMarkupFunction {
        fn markup_field(&self, _field_context: &dyn FieldContext<TestType>, markup_session: &dyn MarkupSession) -> Result<(), Box<dyn std::error::Error>> {
            markup_session.markup(&0 as &dyn Any, false)?;
            Ok(())
        }
    }

    #[test]
    fn markup_function_calls_session_method() {
        let func = CallMarkupFunction;
        let field_ctx = MockFieldContext { test_value: 42 };
        let markup_session = MockMarkupSession { called: std::sync::Arc::new(std::sync::Mutex::new(false)) };

        let result = func.markup_field(&field_ctx, &markup_session);
        assert!(result.is_ok());
        assert!(*markup_session.called.lock().unwrap());
    }
}
