use crate::program::model::data::data_type::DataType;
use crate::program::seam_stubs::PointerTypedefBuilder;

/// Pointer representation used when unable to generate a suitable address.
pub const NAP: &str = "NaP";

/// Interface for pointers.
///
/// Port of `ghidra.program.model.data.Pointer`.
pub trait Pointer: DataType {
    /// Returns the "pointed to" dataType (may be `None`).
    fn get_data_type(&self) -> Option<Box<dyn DataType>>;

    /// Creates a pointer to the indicated data type.
    fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer>;

    /// Construct a pointer-typedef builder based on this pointer.
    fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockPointerTypedefBuilder;
    impl PointerTypedefBuilder for MockPointerTypedefBuilder {}

    struct MockPointer {
        pointee: Option<Box<dyn DataType>>,
    }

    impl DataType for MockPointer {}

    impl Pointer for MockPointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            match &self.pointee {
                Some(_) => Some(Box::new(MockDataType)),
                None => None,
            }
        }

        fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            Box::new(MockPointer {
                pointee: Some(data_type),
            })
        }

        fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
            Box::new(MockPointerTypedefBuilder)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let p = MockPointer { pointee: None };
        let dyn_ptr: &dyn Pointer = &p;
        assert!(dyn_ptr.get_data_type().is_none());
    }

    #[test]
    fn new_pointer_wraps_data_type() {
        let p = MockPointer { pointee: None };
        let p2 = p.new_pointer(Box::new(MockDataType));
        assert!(p2.get_data_type().is_some());
    }

    #[test]
    fn nap_constant() {
        assert_eq!(NAP, "NaP");
    }
}
