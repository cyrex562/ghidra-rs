//! Port of `ghidra.program.model.data.Pointer8DataType`: a [`PointerDataType`] whose length is
//! fixed at 1 byte. The Java class's `ClassTranslator` registration of the legacy name
//! `ghidra.program.model.data.Pointer8` is not ported (no `ClassTranslator` exists here).
//!
//! [`PointerDataType`]: crate::program::model::data::pointer_data_type::PointerDataType

use crate::program::model::data::pointer_data_type::sized_pointer_data_type;

/// The fixed pointer length (in bytes) both Java constructors pass to `super(dt, 1)`.
pub const POINTER8_LENGTH: i32 = 1;

sized_pointer_data_type!(Pointer8DataType, 1, "Pointer8DataType");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::byte_data_type::ByteDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::data::pointer_data_type::PointerDataType;

    #[test]
    fn default_instance_has_fixed_length_and_java_names() {
        let dt = Pointer8DataType::instance();
        assert_eq!(dt.get_name(), "pointer8");
        assert_eq!(dt.get_display_name(), "pointer8");
        assert_eq!(dt.get_length(), POINTER8_LENGTH);
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_description(), "8-bit pointer");
        assert!(dt.get_data_type().is_none());
    }

    #[test]
    fn referenced_pointer_and_class_identity() {
        let dt = Pointer8DataType::new(Some(ByteDataType::data_type())).unwrap();
        assert_eq!(dt.get_name(), "byte *8");
        assert_eq!(dt.get_display_name(), "byte *");
        assert_eq!(dt.get_length(), 1);
        let plain = PointerDataType::to(ByteDataType::data_type(), 1).unwrap();
        // equivalent to a plain pointer of the same length, but a distinct class
        assert!(dt.is_equivalent(&plain));
        assert_ne!(dt.runtime_class(), plain.runtime_class());
    }
}
