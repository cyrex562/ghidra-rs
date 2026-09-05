//! Port of `ghidra.program.model.data.RepeatedStringDataType`.
//!
//! Unlike every other class in this batch, `RepeatedStringDataType` does *not* extend
//! `AbstractStringDataType` -- it `extends RepeatCountDataType`, already ported as a trait
//! ([`RepeatCountDataType`]), so this trait extends it directly. The Java constructor is
//! `super(datatype, null, "RepString", dtm)` where `datatype` is the static field `new
//! StringDataType()` (a repeated element that is itself a whole `StringDataType` instance per
//! repetition, not a single character) and the `null` is the (unused, per
//! [`RepeatCountDataType`]'s own port) `CategoryPath` parameter.
//!
//! `getDescription()` overrides the default `DataType.getDescription()` (already has a default,
//! so -- mirroring every other `BuiltIn`-derived cut-point trait in this crate -- it is exposed
//! here under the distinct name
//! [`repeated_string_description`](RepeatedStringDataType::repeated_string_description)). The
//! inherited `stored_repeat_data_type()` (backing the private `repeatDataType` field) and
//! `clone(DataTypeManager)` are the only other behaviors; `stored_repeat_data_type` is already a
//! required method on the [`RepeatCountDataType`] supertrait (fulfilled directly, not
//! redeclared), and `clone` is exposed as the new required
//! [`repeated_string_clone`](RepeatedStringDataType::repeated_string_clone), mirroring
//! [`StringDataType`](super::string_data_type::StringDataType)'s own `clone` convention.
//!
//! Not ported: the `datatype` static field and `dataType` singleton (both need a concrete,
//! constructible [`StringDataType`] instance, which does not exist yet -- see
//! [`StringDataType`]'s own module docs for why).

use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::repeat_count_data_type::RepeatCountDataType;

/// Port of `RepeatedStringDataType.getDescription()` ("Repeated String").
pub const REPEATED_STRING_DESCRIPTION: &str = "Repeated String";
/// Port of `RepeatedStringDataType.name` ("RepString"), the value passed to `RepeatCountDataType`'s
/// (ultimately `BuiltIn`'s) constructor.
pub const REPEATED_STRING_NAME: &str = "RepString";

/// Some number of repeated strings, each of variable length.
///
/// The data structure looks like this:
/// ```text
///    RepeatedStringDT
///        numberOfStrings = N
///        String1
///        String2
///        ...
///        StringN
/// ```
///
/// Port of `ghidra.program.model.data.RepeatedStringDataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait RepeatedStringDataType: RepeatCountDataType {
    /// Port of `RepeatedStringDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`.
    ///
    /// [`DataType`]: crate::program::model::data::data_type::DataType
    fn repeated_string_description(&self) -> String {
        REPEATED_STRING_DESCRIPTION.to_string()
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager`.
    ///
    /// Port of `RepeatedStringDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`StringDataType`](super::string_data_type::StringDataType)'s module docs for why.
    fn repeated_string_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn RepeatedStringDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::dynamic_data_type::DynamicDataType;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use std::any::Any;
    use std::sync::Arc;

    /// Stand-in for `new StringDataType()`, the repeated element `RepeatedStringDataType` walks.
    /// Only [`DataType::get_length`]/[`DataType::get_name`] are exercised by
    /// [`RepeatCountDataType::repeat_count_all_components`]'s `DataTypeInstance` lookup (through
    /// the non-`Dynamic` branch, since this stand-in has a fixed length), matching the precedent
    /// [`RepeatCountDataType`]'s own tests already established (`OneByteDataType`).
    #[derive(Clone)]
    struct StringPlaceholderDataType;
    impl DataType for StringPlaceholderDataType {
        fn get_name(&self) -> String {
            "string".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            1
        }
    }

    struct FixedMemBuffer {
        bytes: Vec<u8>,
        space: Arc<AddressSpace>,
    }
    impl MemBuffer for FixedMemBuffer {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.bytes.get(start + i) {
                    Some(&b) => {
                        *slot = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_address(&self) -> Address {
            self.space.address(0)
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[derive(Clone)]
    struct MockRepeatedStringDataType;

    impl DataType for MockRepeatedStringDataType {
        fn get_name(&self) -> String {
            REPEATED_STRING_NAME.to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            -1
        }
        fn get_description(&self) -> String {
            self.repeated_string_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.repeat_count_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.repeat_count_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.repeat_count_value(buf, settings, length)
        }
    }

    impl BuiltInDataType for MockRepeatedStringDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockRepeatedStringDataType {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.dynamic_length_from_components(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            false
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.default_replacement_base_type()
        }
    }

    impl DynamicDataType for MockRepeatedStringDataType {
        fn get_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            self.repeat_count_all_components(buf)
        }
    }

    impl RepeatCountDataType for MockRepeatedStringDataType {
        fn stored_repeat_data_type(&self) -> Box<dyn DataType> {
            Box::new(StringPlaceholderDataType)
        }
    }

    impl RepeatedStringDataType for MockRepeatedStringDataType {
        fn repeated_string_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn RepeatedStringDataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn field_values_match_java_constructor() {
        let dt = MockRepeatedStringDataType;
        assert_eq!(dt.get_name(), "RepString");
        assert_eq!(dt.get_description(), "Repeated String");
        assert_eq!(dt.repeated_string_description(), "Repeated String");
    }

    #[test]
    fn stored_repeat_data_type_is_the_repeated_string_element() {
        let dt = MockRepeatedStringDataType;
        assert_eq!(dt.stored_repeat_data_type().get_name(), "string");
    }

    #[test]
    fn all_components_lays_out_repeated_string_elements_after_the_size() {
        // n = 0*16 + 2 + 1 = 3: the Size component plus two 1-byte repeated string elements.
        let dt = MockRepeatedStringDataType;
        let buf = FixedMemBuffer {
            bytes: vec![0x00, 0x02, b'A', b'B'],
            space: ram_space(),
        };
        let comps = dt.repeat_count_all_components(&buf).unwrap();
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0].as_ref().unwrap().get_field_name(), Some("Size".to_string()));
        assert_eq!(comps[1].as_ref().unwrap().get_data_type().get_name(), "string");
        assert_eq!(comps[2].as_ref().unwrap().get_offset(), 3);
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockRepeatedStringDataType;
        let cloned = dt.repeated_string_clone(None);
        assert_eq!(cloned.get_name(), "RepString");
        assert_eq!(cloned.repeated_string_description(), "Repeated String");
    }

    #[test]
    fn clone_with_new_manager_still_reports_the_same_shape() {
        let dt = MockRepeatedStringDataType;
        let cloned = dt.repeated_string_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.stored_repeat_data_type().get_name(), "string");
    }
}
