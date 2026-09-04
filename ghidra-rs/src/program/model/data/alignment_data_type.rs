//! Port of `ghidra.program.model.data.AlignmentDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn implements Dynamic`, so this trait extends both already-ported
//! traits: [`BuiltIn`] and [`Dynamic`] -- mirroring
//! [`AIFFDataType`](super::aiff_data_type::AIFFDataType), which documents the same shape of
//! `BuiltIn + Dynamic` cut-point in more detail.
//!
//! The private `computeLength(MemBuffer)` helper's byte-run-detection loop (walk forward from
//! offset 0 counting repeated bytes, capped at [`ALIGNMENT_MAX_LENGTH`]) is ported faithfully as
//! [`AlignmentDataType::alignment_compute_length`]. Its early-stop check against
//! `listing.getDefinedDataAt(addr)`/`listing.getInstructionAt(addr)` is **not** ported: reaching a
//! `Listing` from a `MemBuffer` here requires `MemBuffer::get_memory()` -> `Memory::get_program()`
//! -> `Program::get_listing()`, and the last of those is modeled in this crate as taking `&mut
//! self` on a `Program` this call only ever observes through a shared `Arc` (borrowed transitively
//! through `buf`), which cannot be exclusively borrowed here. This is a genuine, narrow
//! architectural gap (not specific to `AlignmentDataType`) rather than something a mock can paper
//! over; the byte-run-counting behavior itself -- the substantive part of this class -- is ported
//! and tested faithfully. A future revisit of `Program::get_listing`'s `&mut self` requirement
//! should also update this method to stop early at defined data/instructions, matching Java.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]/
//! [`Dynamic`] (`getLength()`, `getLength(MemBuffer, int)`, `getDescription()`,
//! `getMnemonic(Settings)`, `canSpecifyLength()`, `getRepresentation(...)`, `getValue(...)`,
//! `getValueClass(Settings)`, `getReplacementBaseType()`). Rust does not allow a subtrait to
//! override a supertrait's same-named default without creating an ambiguous call site, so --
//! mirroring [`AIFFDataType`]'s `aiff_*` convention -- those overrides are exposed here under
//! distinct `alignment_*` names. A concrete `impl DataType + BuiltInDataType + Dynamic for ...`
//! should delegate to these; [`Dynamic::get_dynamic_length`]/[`Dynamic::get_replacement_base_type`]
//! have no default at all, so a concrete implementation's overrides should delegate to
//! [`alignment_dynamic_length`](AlignmentDataType::alignment_dynamic_length)/
//! [`alignment_replacement_base_type`](AlignmentDataType::alignment_replacement_base_type)
//! directly.
//!
//! `clone(DataTypeManager)` (overriding `BuiltIn.clone(DataTypeManager)`) is left as a required
//! method (no default), mirroring every other `BuiltIn`-derived cut-point trait in this crate.

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::mem::MemBuffer;

/// Maximum number of repeating bytes [`AlignmentDataType::alignment_compute_length`] will count,
/// standing in for the private `AlignmentDataType.MAX_LENGTH` constant.
pub const ALIGNMENT_MAX_LENGTH: i32 = 1024;

/// Minimal stand-in for `ghidra.program.model.data.ByteDataType.dataType`, used by
/// [`AlignmentDataType::alignment_replacement_base_type`]. Mirrors
/// [`AIFFDataType`](super::aiff_data_type)'s own `BytePlaceholderDataType`.
struct BytePlaceholderDataType;

impl DataType for BytePlaceholderDataType {
    fn get_length(&self) -> i32 {
        1
    }
    fn get_name(&self) -> String {
        "byte".to_string()
    }
}

/// Consumes alignment/repeating bytes -- a dynamically-sized run of identical byte values.
///
/// Port of `ghidra.program.model.data.AlignmentDataType`. See the module docs for the naming
/// conventions used to resolve clashes with [`DataType`]/[`Dynamic`], and for the one piece of
/// `computeLength` left unported.
pub trait AlignmentDataType: BuiltIn + Dynamic {
    /// Port of the private `AlignmentDataType.computeLength(MemBuffer)`, minus the
    /// listing-defined-data early stop; see the module docs.
    ///
    /// Returns the number of consecutive bytes (from offset `0`) equal to the byte at offset `0`,
    /// capped at [`ALIGNMENT_MAX_LENGTH`], or `-1` if no bytes could be read at all.
    fn alignment_compute_length(&self, buf: &dyn MemBuffer) -> i32 {
        let Ok(start_byte) = buf.get_byte(0) else {
            return -1;
        };
        let mut length = 0;
        while length < ALIGNMENT_MAX_LENGTH {
            let Ok(b) = buf.get_byte(length) else {
                break;
            };
            if b != start_byte {
                break;
            }
            length += 1;
        }
        if length > 0 {
            length
        } else {
            -1
        }
    }

    /// Port of `AlignmentDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn alignment_description(&self) -> String {
        "Consumes alignment/repeating bytes.".to_string()
    }

    /// Port of `AlignmentDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`.
    fn alignment_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "align".to_string()
    }

    /// Port of `AlignmentDataType.canSpecifyLength()`, which overrides the default
    /// `Dynamic.canSpecifyLength()`. Always `true`.
    fn alignment_can_specify_length(&self) -> bool {
        true
    }

    /// Port of `AlignmentDataType.getLength()`, which overrides the default `DataType.getLength()`
    /// (which returns `0`, not the `-1` this type reports for its own fixed/undetermined length).
    fn alignment_length(&self) -> i32 {
        -1
    }

    /// Port of `AlignmentDataType.getLength(MemBuffer, int)`, which overrides the abstract
    /// `Dynamic.getLength(MemBuffer, int)` (ported as [`Dynamic::get_dynamic_length`]). Delegates
    /// to [`alignment_compute_length`](Self::alignment_compute_length) when `length` is negative
    /// (unspecified), else passes `length` through unchanged.
    fn alignment_dynamic_length(&self, buf: &dyn MemBuffer, length: i32) -> i32 {
        if length < 0 {
            self.alignment_compute_length(buf)
        } else {
            length
        }
    }

    /// Port of `AlignmentDataType.getRepresentation(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getRepresentation(...)`.
    fn alignment_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings);
        format!("align({length})")
    }

    /// Port of `AlignmentDataType.getValue(MemBuffer, Settings, int)`, which overrides the default
    /// `DataType.getValue(...)`. Returns the same formatted string as
    /// [`alignment_representation`](Self::alignment_representation), boxed as `Any` (standing in
    /// for `Object`).
    fn alignment_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        Some(Box::new(self.alignment_representation(buf, settings, length)) as Box<dyn Any>)
    }

    /// Port of `AlignmentDataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of `String`, standing in for
    /// `String.class`.
    fn alignment_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<String>())
    }

    /// Port of `AlignmentDataType.getReplacementBaseType()`, which overrides the abstract
    /// `Dynamic.getReplacementBaseType()` and returns `ByteDataType.dataType`. See
    /// [`AIFFDataType::aiff_replacement_base_type`](super::aiff_data_type::AIFFDataType::aiff_replacement_base_type)
    /// for why this returns a minimal stand-in rather than a real `ByteDataType` instance.
    fn alignment_replacement_base_type(&self) -> Box<dyn DataType> {
        Box::new(BytePlaceholderDataType)
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `AlignmentDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn alignment_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn AlignmentDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct BytesMemBuffer(Vec<u8>);
    impl MemBuffer for BytesMemBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
    }

    struct MockAlignmentDataType {
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
        parents: Vec<Weak<dyn DataType>>,
    }

    impl MockAlignmentDataType {
        fn new() -> Self {
            Self {
                last_change_time: 0,
                last_change_time_in_source_archive: 0,
                parents: Vec::new(),
            }
        }
    }

    impl DataType for MockAlignmentDataType {
        fn get_name(&self) -> String {
            "Alignment".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.alignment_length()
        }
    }

    impl DataTypeImpl for MockAlignmentDataType {
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
            self.last_change_time
        }
        fn set_stored_last_change_time(&mut self, last_change_time: i64) {
            self.last_change_time = last_change_time;
        }
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            self.last_change_time_in_source_archive
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
            self.last_change_time_in_source_archive = last_change_time;
        }
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            self.parents.clone()
        }
        fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
            self.parents = parents;
        }
    }

    impl BuiltInDataType for MockAlignmentDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockAlignmentDataType {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl Dynamic for MockAlignmentDataType {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.alignment_dynamic_length(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            self.alignment_can_specify_length()
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.alignment_replacement_base_type()
        }
    }

    impl AlignmentDataType for MockAlignmentDataType {
        fn alignment_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn AlignmentDataType> {
            Box::new(MockAlignmentDataType::new())
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockAlignmentDataType::new();
        let dyn_dt: &dyn AlignmentDataType = &dt;
        assert_eq!(dyn_dt.alignment_description(), "Consumes alignment/repeating bytes.");
        assert_eq!(dyn_dt.alignment_mnemonic(&MockSettings), "align");
        assert!(dyn_dt.alignment_can_specify_length());
        assert!(dyn_dt.can_specify_length());
        assert_eq!(dyn_dt.alignment_length(), -1);
        assert_eq!(DataType::get_length(dyn_dt), -1);
        assert_eq!(dyn_dt.alignment_replacement_base_type().get_length(), 1);
    }

    #[test]
    fn compute_length_counts_repeated_leading_bytes() {
        let dt = MockAlignmentDataType::new();
        let buf = BytesMemBuffer(vec![0x90, 0x90, 0x90, 0x00, 0x90]);
        assert_eq!(dt.alignment_compute_length(&buf), 3);
    }

    #[test]
    fn compute_length_caps_at_max_length() {
        let dt = MockAlignmentDataType::new();
        let buf = BytesMemBuffer(vec![0x00; (ALIGNMENT_MAX_LENGTH + 50) as usize]);
        assert_eq!(dt.alignment_compute_length(&buf), ALIGNMENT_MAX_LENGTH);
    }

    #[test]
    fn compute_length_is_negative_one_when_no_bytes_available() {
        let dt = MockAlignmentDataType::new();
        let buf = BytesMemBuffer(Vec::new());
        assert_eq!(dt.alignment_compute_length(&buf), -1);
    }

    #[test]
    fn dynamic_length_uses_computed_length_when_unspecified() {
        let dt = MockAlignmentDataType::new();
        let buf = BytesMemBuffer(vec![1, 1, 1, 2]);
        assert_eq!(dt.alignment_dynamic_length(&buf, -1), 3);
        assert_eq!(dt.get_dynamic_length(&buf, -1), 3);
    }

    #[test]
    fn dynamic_length_passes_through_explicit_length() {
        let dt = MockAlignmentDataType::new();
        let buf = BytesMemBuffer(vec![1, 1, 1, 2]);
        assert_eq!(dt.alignment_dynamic_length(&buf, 7), 7);
    }

    #[test]
    fn representation_and_value_format_align_call() {
        let dt = MockAlignmentDataType::new();
        let buf = BytesMemBuffer(vec![1, 1]);
        assert_eq!(dt.alignment_representation(&buf, &MockSettings, 4), "align(4)");
        let value = dt.alignment_value(&buf, &MockSettings, 4).unwrap();
        assert_eq!(value.downcast_ref::<String>().unwrap(), "align(4)");
        assert_eq!(dt.alignment_value_class(&MockSettings), Some(TypeId::of::<String>()));
    }

    #[test]
    fn clone_produces_a_distinct_alignment_data_type() {
        let dt = MockAlignmentDataType::new();
        let cloned = dt.alignment_clone(None);
        assert_eq!(cloned.alignment_description(), dt.alignment_description());
    }
}
