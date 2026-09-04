//! Port of `ghidra.program.model.data.SegmentedCodePointerDataType`, promoted straight to a
//! trait because it was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn`, already ported as a trait ([`BuiltIn`]), so this trait
//! extends it directly -- mirroring [`VoidDataType`](super::void_data_type::VoidDataType), which
//! documents the same `BuiltIn`-only cut-point shape.
//!
//! `getValue(MemBuffer, Settings, int)` reads a 16-bit segment and a 16-bit offset (each via
//! [`MemBuffer::get_short`]) and combines them into a single `segment << 16 | offset` value,
//! then asks the buffer's own address for a *new* address at that raw value via Java's
//! `Address.getNewAddress(long offset, boolean isAddressableWordOffset)` overload (`true` for the
//! word-offset form) -- ported here as
//! [`AddressSpace::address_from_word_offset`](crate::program::model::address::AddressSpace::address_from_word_offset).
//! Both `MemoryAccessException` (from the reads) and `AddressOutOfBoundsException` (from
//! constructing the new address) collapse to `None`/`"??"`, matching the Java `catch
//! (AddressOutOfBoundsException | MemoryAccessException ex)` doing nothing and falling through to
//! `return null;`.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]
//! (`getMnemonic(Settings)`, `getLength()`, `getDescription()`, `getValue(...)`,
//! `getValueClass(Settings)`, `getRepresentation(...)`). Rust does not allow a subtrait to
//! override a supertrait's same-named default without creating an ambiguous call site, so --
//! mirroring [`VoidDataType`]'s `void_*` convention -- those overrides are exposed here under
//! distinct `segmented_code_pointer_*` names. A concrete `impl DataType + BuiltInDataType for
//! ...` should delegate to these.
//!
//! `clone(DataTypeManager)` is left as a required method (no default), mirroring every other
//! `BuiltIn`-derived cut-point trait in this crate.

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::program::model::address::Address;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::mem::MemBuffer;

/// Port of the `SegmentedCodePointerDataType.getValue(MemBuffer, Settings, int)` body, minus the
/// `Object`/`Settings`/`length` plumbing: computes a code address from a leading 16-bit segment
/// and a trailing 16-bit offset, or `None` on any read/construction failure. See the module docs
/// for the two Java exception types this collapses.
fn segmented_address(buf: &dyn MemBuffer) -> Option<Address> {
    let segment = (buf.get_short(0).ok()? as i64) & 0xffff;
    let offset = (buf.get_short(2).ok()? as i64) & 0xffff;
    let addr_value = (segment << 16) | offset;
    buf.get_address().space().address_from_word_offset(addr_value).ok()
}

/// Provides an implementation of a segmented (16-bit segment : 16-bit offset) code pointer
/// datatype.
///
/// Port of `ghidra.program.model.data.SegmentedCodePointerDataType`. See the module docs for
/// what was ported, added, and omitted.
pub trait SegmentedCodePointerDataType: BuiltIn {
    /// Port of `SegmentedCodePointerDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"segAddr"`.
    fn segmented_code_pointer_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "segAddr".to_string()
    }

    /// Port of `SegmentedCodePointerDataType.getLength()`, which overrides the default
    /// `DataType.getLength()` (which returns `0`, not the `4` this type reports).
    fn segmented_code_pointer_length(&self) -> i32 {
        4
    }

    /// Port of `SegmentedCodePointerDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn segmented_code_pointer_description(&self) -> String {
        "Code address from 16 bit segment and 16 bit offset".to_string()
    }

    /// Port of `SegmentedCodePointerDataType.getValue(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getValue(...)`. See [`segmented_address`] for the computation and
    /// what collapses to `None`.
    fn segmented_code_pointer_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        segmented_address(buf).map(|addr| Box::new(addr) as Box<dyn Any>)
    }

    /// Port of `SegmentedCodePointerDataType.getValueClass(Settings)`, which overrides the
    /// default `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of [`Address`],
    /// standing in for `Address.class`.
    fn segmented_code_pointer_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<Address>())
    }

    /// Port of `SegmentedCodePointerDataType.getRepresentation(MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.getRepresentation(...)`. `"??"` when
    /// [`segmented_code_pointer_value`](Self::segmented_code_pointer_value) is `None`, otherwise
    /// the computed address's `Display` string (matching the Java `obj.toString()` fallthrough).
    fn segmented_code_pointer_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = length;
        match segmented_address(buf) {
            Some(addr) => addr.to_string(),
            None => "??".to_string(),
        }
    }

    /// Port of `SegmentedCodePointerDataType.clone(DataTypeManager)`. Left as a required method
    /// (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn segmented_code_pointer_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn SegmentedCodePointerDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::{Arc, Weak};

    struct MockSettings;
    impl Settings for MockSettings {}

    fn code_space() -> Arc<AddressSpace> {
        AddressSpace::new("CODE", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct MockBuf {
        bytes: [u8; 4],
        space: Arc<AddressSpace>,
    }
    impl MemBuffer for MockBuf {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.bytes.get(start + i) {
                    Some(&byte) => {
                        *slot = byte;
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

    #[derive(Clone)]
    struct MockSegmentedCodePointer;

    impl DataType for MockSegmentedCodePointer {
        fn get_name(&self) -> String {
            "SegmentedCodeAddress".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.segmented_code_pointer_length()
        }
        fn get_description(&self) -> String {
            self.segmented_code_pointer_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.segmented_code_pointer_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.segmented_code_pointer_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.segmented_code_pointer_value(buf, settings, length)
        }
    }

    impl DataTypeImpl for MockSegmentedCodePointer {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            Vec::new()
        }
        fn set_stored_parent_refs(&mut self, _parents: Vec<Weak<dyn DataType>>) {}
    }

    impl BuiltInDataType for MockSegmentedCodePointer {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockSegmentedCodePointer {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl SegmentedCodePointerDataType for MockSegmentedCodePointer {
        fn segmented_code_pointer_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn SegmentedCodePointerDataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockSegmentedCodePointer;
        let dyn_dt: &dyn SegmentedCodePointerDataType = &dt;
        assert_eq!(dyn_dt.segmented_code_pointer_length(), 4);
        assert_eq!(
            dyn_dt.segmented_code_pointer_description(),
            "Code address from 16 bit segment and 16 bit offset"
        );
        assert_eq!(dyn_dt.segmented_code_pointer_mnemonic(&MockSettings), "segAddr");
        assert_eq!(
            dyn_dt.segmented_code_pointer_value_class(&MockSettings),
            Some(TypeId::of::<Address>())
        );
    }

    #[test]
    fn value_combines_segment_and_offset_into_a_word_offset_address() {
        let dt = MockSegmentedCodePointer;
        let space = code_space();
        // segment=0x0001, offset=0x0002 -> addr_value = (1 << 16) | 2 = 0x10002.
        let buf = MockBuf { bytes: [0x00, 0x01, 0x00, 0x02], space: space.clone() };
        let value = dt.segmented_code_pointer_value(&buf, &MockSettings, 4).unwrap();
        let addr = value.downcast_ref::<Address>().unwrap();
        assert_eq!(addr.offset(), 0x10002);
        assert_eq!(addr.space().name(), space.name());
    }

    #[test]
    fn representation_matches_the_computed_address_display() {
        let dt = MockSegmentedCodePointer;
        let space = code_space();
        let buf = MockBuf { bytes: [0x00, 0x01, 0x00, 0x02], space: space.clone() };
        let value = dt.segmented_code_pointer_value(&buf, &MockSettings, 4).unwrap();
        let addr = value.downcast_ref::<Address>().unwrap();
        assert_eq!(
            dt.segmented_code_pointer_representation(&buf, &MockSettings, 4),
            addr.to_string()
        );
    }

    #[test]
    fn representation_is_question_marks_when_the_read_fails() {
        struct FailingBuf {
            space: Arc<AddressSpace>,
        }
        impl MemBuffer for FailingBuf {
            fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
                0 // always a short (failed) read, matching `get_byte`'s unconditional error
            }
            fn is_big_endian(&self) -> bool {
                true
            }
            fn get_address(&self) -> Address {
                self.space.address(0)
            }
            fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
                Err(MemoryAccessException::new("no bytes available"))
            }
        }

        let dt = MockSegmentedCodePointer;
        let buf = FailingBuf { space: code_space() };
        assert!(dt.segmented_code_pointer_value(&buf, &MockSettings, 4).is_none());
        assert_eq!(dt.segmented_code_pointer_representation(&buf, &MockSettings, 4), "??");
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockSegmentedCodePointer;
        let cloned = dt.segmented_code_pointer_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}
