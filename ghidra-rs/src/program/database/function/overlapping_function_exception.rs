use crate::program::database::symbol::OverlappingNamespaceException;
use crate::program::model::address::Address;
use std::fmt;

/// Exception thrown when attempting to create a function at an address that overlaps
/// with an existing namespace.
///
/// Port of `ghidra.program.database.function.OverlappingFunctionException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlappingFunctionException {
    message: String,
}

impl OverlappingFunctionException {
    /// Creates an exception for a function overlapping with a namespace.
    ///
    /// # Arguments
    /// * `entry_point` - the address where the function creation was attempted
    /// * `e` - the overlapping namespace exception
    pub fn from_namespace_exception(
        entry_point: Address,
        e: &OverlappingNamespaceException,
    ) -> Self {
        let message = format!(
            "Unable to create function at {} due to overlap with range [{},{}]",
            entry_point.offset(),
            e.start().offset(),
            e.end().offset()
        );
        Self { message }
    }

    /// Creates an exception for a function overlapping with another namespace.
    ///
    /// # Arguments
    /// * `entry_point` - the address where the function creation was attempted
    pub fn from_entry_point(entry_point: Address) -> Self {
        let message = format!(
            "Unable to create function at {} due to overlap with another namespace",
            entry_point.offset()
        );
        Self { message }
    }

    /// Creates an exception with the given message.
    ///
    /// # Arguments
    /// * `msg` - the exception message
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for OverlappingFunctionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OverlappingFunctionException {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn create_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn from_namespace_exception_creates_detailed_message() {
        let entry_point = create_address(0x1000);
        let start = create_address(0x2000);
        let end = create_address(0x3000);
        let ns_exc = OverlappingNamespaceException::new(start, end);

        let exc = OverlappingFunctionException::from_namespace_exception(
            entry_point.clone(),
            &ns_exc,
        );

        assert_eq!(
            exc.message(),
            "Unable to create function at 4096 due to overlap with range [8192,12288]"
        );
        assert!(exc.to_string().contains("4096"));
        assert!(exc.to_string().contains("8192"));
        assert!(exc.to_string().contains("12288"));
    }

    #[test]
    fn from_entry_point_creates_generic_message() {
        let entry_point = create_address(0x5000);
        let exc = OverlappingFunctionException::from_entry_point(entry_point);

        assert_eq!(
            exc.message(),
            "Unable to create function at 20480 due to overlap with another namespace"
        );
        assert!(exc.to_string().contains("20480"));
    }

    #[test]
    fn new_with_custom_message() {
        let msg = "Custom error message";
        let exc = OverlappingFunctionException::new(msg);

        assert_eq!(exc.message(), msg);
        assert_eq!(exc.to_string(), msg);
    }

    #[test]
    fn new_with_string() {
        let msg = "Error as String".to_string();
        let exc = OverlappingFunctionException::new(msg.clone());

        assert_eq!(exc.message(), msg);
    }

    #[test]
    fn display_uses_message() {
        let exc = OverlappingFunctionException::new("test message");
        assert_eq!(format!("{}", exc), "test message");
    }

    #[test]
    fn debug_format_contains_type_name() {
        let exc = OverlappingFunctionException::new("debug test");
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("OverlappingFunctionException"));
    }

    #[test]
    fn implements_error_trait() {
        let exc = OverlappingFunctionException::new("error trait test");
        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn clone_produces_equal_exception() {
        let exc1 = OverlappingFunctionException::new("cloned test");
        let exc2 = exc1.clone();

        assert_eq!(exc1, exc2);
        assert_eq!(exc1.message(), exc2.message());
    }

    #[test]
    fn equality_works() {
        let exc1 = OverlappingFunctionException::new("same");
        let exc2 = OverlappingFunctionException::new("same");
        let exc3 = OverlappingFunctionException::new("different");

        assert_eq!(exc1, exc2);
        assert_ne!(exc1, exc3);
    }
}
