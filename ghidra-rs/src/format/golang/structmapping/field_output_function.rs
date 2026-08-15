use crate::format::seam_stubs::{FieldOutputInfo, StructureContext};
use crate::program::model::data::structure::Structure;

/// A function that adds a field to a Ghidra structure using annotated field information
/// found in a Java class.
///
/// This is the Rust equivalent of the Java `FieldOutputFunction<T>` functional interface
/// from `ghidra.app.util.bin.format.golang.structmapping`.
///
/// In Java the interface declares a single method:
/// ```java
/// void addFieldToStructure(StructureContext<T> context, Structure structure,
///         FieldOutputInfo<T> fieldOutputInfo) throws IOException;
/// ```
/// In Rust this is expressed as a trait with a generic type parameter.
pub trait FieldOutputFunction<T> {
    /// Adds the specified field to the structure.
    ///
    /// # Arguments
    ///
    /// * `context` - information about the structure context
    /// * `structure` - the structure data type to add the field to
    /// * `field_output_info` - information about the field to add
    ///
    /// # Errors
    ///
    /// Returns an error if the field cannot be added to the structure.
    fn add_field_to_structure(
        &self,
        context: &dyn StructureContext<T>,
        structure: &mut dyn Structure,
        field_output_info: &dyn FieldOutputInfo<T>,
    ) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestType;

    struct SimpleOutputFunction;

    impl FieldOutputFunction<TestType> for SimpleOutputFunction {
        fn add_field_to_structure(
            &self,
            _context: &dyn StructureContext<TestType>,
            _structure: &mut dyn Structure,
            _field_output_info: &dyn FieldOutputInfo<TestType>,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn field_output_function_trait_is_implementable() {
        let _func = SimpleOutputFunction;
    }

    struct ErrorOutputFunction;

    impl FieldOutputFunction<TestType> for ErrorOutputFunction {
        fn add_field_to_structure(
            &self,
            _context: &dyn StructureContext<TestType>,
            _structure: &mut dyn Structure,
            _field_output_info: &dyn FieldOutputInfo<TestType>,
        ) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "test error",
            ))
        }
    }

    #[test]
    fn field_output_function_can_return_error() {
        let func = ErrorOutputFunction;
        // Note: we can't easily test this without mock implementations of Structure,
        // StructureContext, and FieldOutputInfo, but we can verify the trait exists
        // and can be implemented with error-returning behavior.
        let _func_trait_object: &dyn FieldOutputFunction<TestType> = &func;
    }
}
