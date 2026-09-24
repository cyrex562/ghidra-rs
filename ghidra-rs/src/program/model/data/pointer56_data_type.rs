//! Port of `ghidra.program.model.data.Pointer56DataType`.
//!
//! The Java class `extends PointerDataType`, already ported as a trait
//! ([`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType)), so
//! this trait extends it directly. Unlike every sibling `PointerN`/fixed-size cut-point trait in
//! this crate, `Pointer56DataType` contributes **no method overrides at all** -- its entire body
//! is two constructors (`Pointer56DataType()`/`Pointer56DataType(DataType dt)`, both forwarding to
//! `super(dt, 7)`, fixing the pointer length at 7 bytes) plus a `static { ClassTranslator.put(...) }`
//! registration of the legacy class name `ghidra.program.model.data.Pointer56`.
//!
//! Neither is representable on a trait: traits cannot declare constructors or store fields (so the
//! fixed-length-7 behavior has nowhere to live except
//! [`PointerDataType::stored_length`](crate::program::model::data::pointer_data_type::PointerDataType::stored_length),
//! which a concrete implementation must simply initialize to [`POINTER56_LENGTH`]), and
//! `ClassTranslator` is not ported (mirroring every other `ClassTranslator.put` registration
//! already skipped elsewhere in this crate, e.g.
//! [`UnsignedInteger3DataType`](super::unsigned_integer3_data_type::UnsignedInteger3DataType)'s
//! own module docs).
//!
//! This trait is therefore a marker/re-export with no new methods: a concrete implementation
//! satisfies it entirely by implementing [`PointerDataType`] with
//! `stored_length()` fixed at [`POINTER56_LENGTH`].
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::pointer_data_type::PointerDataType;

/// Fixed pointer length (in bytes) for a [`Pointer56DataType`], standing in for the literal `7`
/// passed to the `PointerDataType(DataType, int)` superclass constructor by both
/// `Pointer56DataType` constructors.
pub const POINTER56_LENGTH: i32 = 7;

/// Pointer56 is really a factory for generating 7-byte pointers.
///
/// Port of `ghidra.program.model.data.Pointer56DataType`. See the module-level documentation for
/// why this trait adds no new methods beyond what
/// [`PointerDataType`] already provides.
pub trait Pointer56DataType: PointerDataType {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder;

            /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization() -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        // Deliberately different from the fixed pointer length, so tests can confirm the
        // *stored* fixed length wins over the data organization's native pointer size.
        org.set_pointer_size(8);
        org.set_big_endian(false);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(2);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(0);
        org.set_machine_alignment(8);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(8);
        org.clear_size_alignment_map();
        org
    }

    struct MockPointer56DataType {
        referenced: Option<Box<dyn DataType>>,
    }

    impl DataType for MockPointer56DataType {
        fn get_name(&self) -> String {
            self.pointer_data_type_impl_name()
        }
        fn get_length(&self) -> i32 {
            self.pointer_data_type_impl_length()
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            Arc::new(mock_data_organization())
        }
        fn is_pointer(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockPointer56DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Pointer for MockPointer56DataType {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            self.pointer_data_type_impl_get_data_type()
        }
        fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            Box::new(MockPointer56DataType {
                referenced: Some(data_type),
            })
        }
        fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl PointerDataType for MockPointer56DataType {
        fn stored_referenced_data_type(&self) -> Option<Box<dyn DataType>> {
            self.referenced.as_ref().map(|dt| clone_mock(dt.as_ref()))
        }
        fn set_stored_referenced_data_type(&mut self, referenced_data_type: Option<Box<dyn DataType>>) {
            self.referenced = referenced_data_type;
        }
        fn stored_length(&self) -> i32 {
            POINTER56_LENGTH
        }
        fn set_stored_length(&mut self, _length: i32) {
            // Pointer56DataType's length is always fixed at POINTER56_LENGTH; a real
            // implementation would reject/ignore attempts to change it, mirroring the Java class
            // never exposing a mutator for its constructor-fixed length.
        }
        fn stored_deleted(&self) -> bool {
            false
        }
        fn set_stored_deleted(&mut self, _deleted: bool) {}
    }

    impl Pointer56DataType for MockPointer56DataType {}

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
        let dt = MockPointer56DataType { referenced: None };
        let dyn_dt: &dyn Pointer56DataType = &dt;
        assert_eq!(dyn_dt.stored_length(), POINTER56_LENGTH);
    }

    #[test]
    fn length_is_fixed_at_7_bytes_regardless_of_data_organization_pointer_size() {
        let dt = MockPointer56DataType { referenced: None };
        // The mock DataOrganization reports an 8-byte native pointer size, but a Pointer56DataType
        // always reports 7 -- exactly mirroring `super(dt, 7)` fixing the Java `length` field.
        assert_eq!(DataType::get_length(&dt), POINTER56_LENGTH);
        assert_eq!(dt.get_data_organization().get_pointer_size(), 8);
    }

    #[test]
    fn display_name_reflects_pointer_arithmetic_over_stored_length() {
        let untyped = MockPointer56DataType { referenced: None };
        assert_eq!(untyped.pointer_data_type_impl_display_name(), "pointer56");

        let typed = MockPointer56DataType {
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
