//! Port of `ghidra.program.model.data.Pointer24DataType`.
//!
//! The Java class `extends PointerDataType`, already ported as a trait
//! ([`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType)), so
//! this trait extends it directly. Unlike every sibling `PointerN`/fixed-size cut-point trait in
//! this crate, `Pointer24DataType` contributes **no method overrides at all** -- its entire body
//! is two constructors (`Pointer24DataType()`/`Pointer24DataType(DataType dt)`, both forwarding to
//! `super(dt, 3)`, fixing the pointer length at 3 bytes) plus a `static { ClassTranslator.put(...) }`
//! registration of the legacy class name `ghidra.program.model.data.Pointer24`.
//!
//! Neither is representable on a trait: traits cannot declare constructors or store fields (so the
//! fixed-length-3 behavior has nowhere to live except
//! [`PointerDataType::stored_length`](crate::program::model::data::pointer_data_type::PointerDataType::stored_length),
//! which a concrete implementation must simply initialize to [`POINTER24_LENGTH`]), and
//! `ClassTranslator` is not ported (mirroring every other `ClassTranslator.put` registration
//! already skipped elsewhere in this crate, e.g.
//! [`UnsignedInteger3DataType`](super::unsigned_integer3_data_type::UnsignedInteger3DataType)'s
//! own module docs).
//!
//! This trait is therefore a marker/re-export with no new methods: a concrete implementation
//! satisfies it entirely by implementing [`PointerDataType`] with
//! `stored_length()` fixed at [`POINTER24_LENGTH`].
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::pointer_data_type::PointerDataType;

/// Fixed pointer length (in bytes) for a [`Pointer24DataType`], standing in for the literal `3`
/// passed to the `PointerDataType(DataType, int)` superclass constructor by both
/// `Pointer24DataType` constructors.
pub const POINTER24_LENGTH: i32 = 3;

/// Pointer24 is really a factory for generating 3-byte pointers.
///
/// Port of `ghidra.program.model.data.Pointer24DataType`. See the module-level documentation for
/// why this trait adds no new methods beyond what
/// [`PointerDataType`] already provides.
pub trait Pointer24DataType: PointerDataType {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder;

    struct MockBitFieldPacking;
    impl crate::program::model::data::bit_field_packing::BitFieldPacking for MockBitFieldPacking {
        fn use_ms_convention(&self) -> bool {
            false
        }
        fn is_type_alignment_enabled(&self) -> bool {
            true
        }
        fn get_zero_length_boundary(&self) -> i32 {
            0
        }
    }

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            // Deliberately different from POINTER24_LENGTH, so tests can confirm the *stored*
            // fixed length (3) wins over whatever the data organization's native pointer size is.
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct MockPointer24DataType {
        referenced: Option<Box<dyn DataType>>,
    }

    impl DataType for MockPointer24DataType {
        fn get_name(&self) -> String {
            self.pointer_data_type_impl_name()
        }
        fn get_length(&self) -> i32 {
            self.pointer_data_type_impl_length()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn is_pointer(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockPointer24DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Pointer for MockPointer24DataType {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            self.pointer_data_type_impl_get_data_type()
        }
        fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            Box::new(MockPointer24DataType {
                referenced: Some(data_type),
            })
        }
        fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl PointerDataType for MockPointer24DataType {
        fn stored_referenced_data_type(&self) -> Option<Box<dyn DataType>> {
            self.referenced.as_ref().map(|dt| clone_mock(dt.as_ref()))
        }
        fn set_stored_referenced_data_type(&mut self, referenced_data_type: Option<Box<dyn DataType>>) {
            self.referenced = referenced_data_type;
        }
        fn stored_length(&self) -> i32 {
            POINTER24_LENGTH
        }
        fn set_stored_length(&mut self, _length: i32) {
            // Pointer24DataType's length is always fixed at POINTER24_LENGTH; a real
            // implementation would reject/ignore attempts to change it, mirroring the Java class
            // never exposing a mutator for its constructor-fixed length.
        }
        fn stored_deleted(&self) -> bool {
            false
        }
        fn set_stored_deleted(&mut self, _deleted: bool) {}
    }

    impl Pointer24DataType for MockPointer24DataType {}

    /// Minimal `DataType` clone helper, standing in for a real referenced-data-type registry this
    /// smoke test does not need.
    fn clone_mock(dt: &dyn DataType) -> Box<dyn DataType> {
        struct Cloned {
            name: String,
            length: i32,
        }
        impl DataType for Cloned {
            fn get_name(&self) -> String {
                self.name.clone()
            }
            fn get_length(&self) -> i32 {
                self.length
            }
        }
        Box::new(Cloned {
            name: dt.get_name(),
            length: dt.get_length(),
        })
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockPointer24DataType { referenced: None };
        let dyn_dt: &dyn Pointer24DataType = &dt;
        assert_eq!(dyn_dt.stored_length(), POINTER24_LENGTH);
    }

    #[test]
    fn length_is_fixed_at_3_bytes_regardless_of_data_organization_pointer_size() {
        let dt = MockPointer24DataType { referenced: None };
        // The mock DataOrganization reports an 8-byte native pointer size, but a Pointer24DataType
        // always reports 3 -- exactly mirroring `super(dt, 3)` fixing the Java `length` field.
        assert_eq!(DataType::get_length(&dt), POINTER24_LENGTH);
        assert_eq!(dt.get_data_organization().get_pointer_size(), 8);
    }

    #[test]
    fn display_name_reflects_pointer_arithmetic_over_stored_length() {
        let untyped = MockPointer24DataType { referenced: None };
        assert_eq!(untyped.pointer_data_type_impl_display_name(), "pointer24");

        let typed = MockPointer24DataType {
            referenced: Some(Box::new({
                struct Named;
                impl DataType for Named {
                    fn get_name(&self) -> String {
                        "int".to_string()
                    }
                    fn get_display_name(&self) -> String {
                        "int".to_string()
                    }
                }
                Named
            })),
        };
        assert_eq!(typed.pointer_data_type_impl_display_name(), "int *");
    }
}
