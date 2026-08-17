//! Port of `ghidra.program.model.data.AIFFDataType`, promoted to a trait because it was selected
//! as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn implements Dynamic`, so this trait extends both already-ported
//! traits: [`BuiltIn`] and [`Dynamic`].
//!
//! Several methods here share a name with an already-provided method on [`DataType`]/[`Dynamic`]
//! (`getLength()` vs. [`DataType::get_length`], `getLength(MemBuffer, int)` vs.
//! [`Dynamic::get_dynamic_length`], `getDescription()` vs. [`DataType::get_description`],
//! `getMnemonic(Settings)` vs. [`DataType::get_mnemonic`], `getRepresentation(...)` vs.
//! [`DataType::get_representation`], `getValue(...)` vs. [`DataType::get_value`],
//! `getValueClass(Settings)` vs. [`DataType::get_value_class`], `getDefaultLabelPrefix(...)` vs.
//! [`DataType::get_default_label_prefix_for_data`], `getReplacementBaseType()` vs.
//! [`Dynamic::get_replacement_base_type`]). Rust does not allow a subtrait to override a
//! supertrait's same-named default without creating an ambiguous call site, so -- mirroring
//! [`ByteDataType`](super::byte_data_type::ByteDataType)'s `byte_*` convention -- those overrides
//! are exposed here under distinct `aiff_*` names. A concrete `impl DataType + BuiltInDataType +
//! Dynamic for ...` should delegate to these; [`Dynamic::get_replacement_base_type`] has no
//! default at all, so a concrete implementation's override should delegate to
//! [`aiff_replacement_base_type`](Self::aiff_replacement_base_type) directly.
//!
//! `canSpecifyLength()` is *not* redeclared here: it always returns `false`, exactly
//! [`Dynamic::can_specify_length`]'s existing default.
//!
//! `clone(DataTypeManager)` (overriding `BuiltIn.clone(DataTypeManager)`) is left as a required
//! method (no default) since the real implementation returns `self` when `dtm` already matches
//! this instance's manager, which requires manager-identity comparison a mock cannot provide
//! generically -- mirroring [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone).
//!
//! `getValue`'s real return type is `ghidra.program.model.data.AudioPlayer`, which is not yet
//! ported (it also implements Swing-facing `Playable`/`LineListener` for GUI audio playback, well
//! outside this crate's scope so far); see the
//! [`AudioPlayer`](crate::program::seam_stubs::AudioPlayer) placeholder in `seam_stubs.rs`.
//!
//! Static state translated as module-level constants: `MAGIC_AIFF`/`MAGIC_AIFC`/`MAGIC_MASK`. The
//! private `checkMagic(MemBuffer, byte[])` helper is ported as the free function
//! [`check_magic`], since it does not depend on instance state.

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::seam_stubs::{AudioPlayer, AudioPlayerImpl};
use crate::program::model::mem::MemBuffer;

/// Magic bytes for the 'AIFF' audio file header.
pub const MAGIC_AIFF: [u8; 12] = [
    b'F', b'O', b'R', b'M', 0x00, 0x00, 0x00, 0x00, b'A', b'I', b'F', b'F',
];

/// Magic bytes for the 'AIFC' audio file header (almost same as AIFF).
pub const MAGIC_AIFC: [u8; 12] = [
    b'F', b'O', b'R', b'M', 0x00, 0x00, 0x00, 0x00, b'A', b'I', b'F', b'C',
];

/// Byte search mask for the magic bytes above.
pub const MAGIC_MASK: [u8; 12] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// Port of the private `AIFFDataType.checkMagic(MemBuffer, byte[])`.
///
/// Returns `true` if every byte of `buf` (masked by [`MAGIC_MASK`]) matches `magic_bytes`. A
/// memory access failure is treated the same as a mismatch, mirroring how the only caller
/// (`getLength(MemBuffer, int)`) wraps both `checkMagic` calls and the subsequent `getInt` in a
/// single try/catch that returns `-1` on any exception.
pub fn check_magic(buf: &dyn MemBuffer, magic_bytes: &[u8]) -> bool {
    for (i, &expected) in magic_bytes.iter().enumerate() {
        let Ok(actual) = buf.get_byte(i as i32) else {
            return false;
        };
        if expected != (actual as u8 & MAGIC_MASK[i]) {
            return false;
        }
    }
    true
}

/// AIFF / AIFC header format:
/// ```text
/// struct {
///     int32 ckID;             'FORM'
///     int32 ckDataSize;
///     int32 formType;         'AIFF', 'AIFC'
///     -variable length chunk data-
/// }
/// ```
///
/// Port of `ghidra.program.model.data.AIFFDataType`. See the module docs for the naming
/// conventions used to resolve clashes with [`DataType`]/[`Dynamic`], and for what was left
/// required.
pub trait AIFFDataType: BuiltIn + Dynamic {
    /// Port of `AIFFDataType.getLength()`, which overrides the abstract `DataType.getLength()`
    /// and always returns `-1` (length is unknown until computed from real data).
    fn aiff_length(&self) -> i32 {
        -1
    }

    /// Port of `AIFFDataType.getLength(MemBuffer, int)`, which overrides
    /// `Dynamic.getLength(MemBuffer, int)` (ported as [`Dynamic::get_dynamic_length`]).
    ///
    /// `max_length` is accepted only to match the overridden signature; like the Java
    /// implementation, it is not used in computing the result.
    ///
    /// Returns the data length (`ckDataSize + 8`), or `-1` if `buf` does not start with a
    /// recognized AIFF/AIFC magic header or its declared `ckDataSize` is not positive.
    fn aiff_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        let _ = max_length;
        if !check_magic(buf, &MAGIC_AIFF) && !check_magic(buf, &MAGIC_AIFC) {
            return -1;
        }
        match buf.get_int(4) {
            Ok(data_size) if data_size > 0 => data_size + 8,
            _ => -1,
        }
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `AIFFDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see the module
    /// docs for why.
    fn aiff_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn AIFFDataType>;

    /// Port of `AIFFDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`.
    fn aiff_description(&self) -> String {
        "AIFF sound stored within program".to_string()
    }

    /// Port of `AIFFDataType.getMnemonic(Settings)`, which overrides the abstract
    /// `DataType.getMnemonic(Settings)`.
    fn aiff_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "AIFF".to_string()
    }

    /// Port of `AIFFDataType.getRepresentation(MemBuffer, Settings, int)`, which overrides the
    /// abstract `DataType.getRepresentation(MemBuffer, Settings, int)`.
    fn aiff_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        "<AIFF-Representation>".to_string()
    }

    /// Port of `AIFFDataType.getValue(MemBuffer, Settings, int)`, which overrides the abstract
    /// `DataType.getValue(MemBuffer, Settings, int)`.
    ///
    /// Returns `None` if fewer than `length` bytes are available in `buf`, otherwise a boxed
    /// [`AudioPlayer`] placeholder wrapping the raw bytes (standing in for `new
    /// AudioPlayer(data)`; see the module docs).
    fn aiff_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = settings;
        let mut data = vec![0u8; length.max(0) as usize];
        if buf.get_bytes_into(&mut data, 0) != length {
            return None;
        }
        Some(Box::new(AudioPlayerImpl::new(data)) as Box<dyn Any>)
    }

    /// Port of `AIFFDataType.getValueClass(Settings)`, which overrides
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of the concrete
    /// [`AudioPlayerImpl`] placeholder used by [`aiff_value`](Self::aiff_value), standing in for
    /// `AudioPlayer.class`.
    fn aiff_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<AudioPlayerImpl>())
    }

    /// Port of `AIFFDataType.getDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, which overrides
    /// `DataType.getDefaultLabelPrefix(MemBuffer, Settings, int, DataTypeDisplayOptions)`
    /// (ported as [`DataType::get_default_label_prefix_for_data`]).
    fn aiff_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let _ = (buf, settings, len, options);
        Some("AIFF".to_string())
    }

    /// Port of `AIFFDataType.getReplacementBaseType()`, which overrides the abstract
    /// `Dynamic.getReplacementBaseType()` and returns `ByteDataType.dataType`.
    /// [`ByteDataType`](super::byte_data_type::ByteDataType) has itself been promoted to a trait
    /// with no singleton instance, so this returns a minimal stand-in with the same 1-byte
    /// length, mirroring
    /// [`DynamicDataType::default_replacement_base_type`](super::dynamic_data_type::DynamicDataType::default_replacement_base_type).
    fn aiff_replacement_base_type(&self) -> Box<dyn DataType> {
        Box::new(BytePlaceholderDataType)
    }
}

/// Minimal stand-in for `ghidra.program.model.data.ByteDataType.dataType`, used by
/// [`AIFFDataType::aiff_replacement_base_type`].
struct BytePlaceholderDataType;

impl DataType for BytePlaceholderDataType {
    fn get_length(&self) -> i32 {
        1
    }

    fn get_name(&self) -> String {
        "byte".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings_definition::SettingsDefinition;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    /// A [`MemBuffer`] backed by an in-memory byte slice, used to exercise
    /// [`check_magic`]/[`AIFFDataType::aiff_dynamic_length`]/[`AIFFDataType::aiff_value`] against
    /// real header-parsing behavior rather than trivially-true stubs.
    struct BytesMemBuffer(Vec<u8>);

    impl MemBuffer for BytesMemBuffer {
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .map(|&b| b )
                .ok_or_else(MemoryAccessException::default)
        }

        fn get_int(&self, offset: i32) -> Result<i32, MemoryAccessException> {
            let start = offset as usize;
            let bytes: [u8; 4] = self
                .0
                .get(start..start + 4)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(MemoryAccessException::default)?;
            Ok(i32::from_be_bytes(bytes))
        }

        fn get_bytes(&self, buffer: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let available = self.0.len().saturating_sub(start);
            let n = available.min(buffer.len());
            buffer[..n].copy_from_slice(&self.0[start..start + n]);
            n 
        }
    }

    fn aiff_header(kind: &[u8; 4], data_size: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FORM");
        bytes.extend_from_slice(&data_size.to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes
    }

    // Every `set_stored_*` below takes `&mut self`, so the stored state needs no interior
    // mutability; plain fields also keep this mock `Send + Sync`, as `DataType` requires. The
    // settings and source-archive boxes are dropped entirely, since the mock's getters always
    // answer with a fresh `MockSettings`/`None` and `dyn Settings`/`dyn SourceArchive` are
    // themselves neither `Send` nor `Sync`.
    struct MockAIFFDataType {
        name: String,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
        parents: Vec<Weak<dyn DataType>>,
    }

    impl MockAIFFDataType {
        fn new() -> Self {
            Self {
                name: "AIFF-Sound".to_string(),
                last_change_time: 0,
                last_change_time_in_source_archive: 0,
                parents: Vec::new(),
            }
        }
    }

    impl DataType for MockAIFFDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            -1
        }
    }

    impl DataTypeImpl for MockAIFFDataType {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn crate::program::model::data::source_archive::SourceArchive>> {
            None
        }
        fn set_stored_source_archive(
            &mut self,
            _archive: Option<Box<dyn crate::program::model::data::source_archive::SourceArchive>>,
        ) {
        }
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

    impl BuiltInDataType for MockAIFFDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockAIFFDataType {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl Dynamic for MockAIFFDataType {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.aiff_dynamic_length(buf, max_length)
        }

        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.aiff_replacement_base_type()
        }
    }

    impl AIFFDataType for MockAIFFDataType {
        fn aiff_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn AIFFDataType> {
            Box::new(MockAIFFDataType::new())
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockAIFFDataType::new();
        let dyn_dt: &dyn AIFFDataType = &dt;
        assert_eq!(dyn_dt.aiff_length(), -1);
        assert_eq!(dyn_dt.aiff_description(), "AIFF sound stored within program");
        assert_eq!(dyn_dt.aiff_mnemonic(&MockSettings), "AIFF");
        assert!(!dyn_dt.can_specify_length());
        assert_eq!(dyn_dt.aiff_replacement_base_type().get_length(), 1);
    }

    #[test]
    fn dynamic_length_recognizes_aiff_and_aifc_magic() {
        let dt = MockAIFFDataType::new();
        let aiff_buf = BytesMemBuffer(aiff_header(b"AIFF", 100));
        assert_eq!(dt.aiff_dynamic_length(&aiff_buf, -1), 108);

        let aifc_buf = BytesMemBuffer(aiff_header(b"AIFC", 42));
        assert_eq!(dt.aiff_dynamic_length(&aifc_buf, -1), 50);
    }

    #[test]
    fn dynamic_length_rejects_bad_magic_or_nonpositive_size() {
        let dt = MockAIFFDataType::new();
        let bad_magic = BytesMemBuffer(aiff_header(b"WAVE", 100));
        assert_eq!(dt.aiff_dynamic_length(&bad_magic, -1), -1);

        let bad_size = BytesMemBuffer(aiff_header(b"AIFF", 0));
        assert_eq!(dt.aiff_dynamic_length(&bad_size, -1), -1);

        let too_short = BytesMemBuffer(vec![b'F', b'O']);
        assert_eq!(dt.aiff_dynamic_length(&too_short, -1), -1);
    }

    #[test]
    fn check_magic_respects_mask_dont_care_bytes() {
        // Bytes 4..8 (the ckDataSize field) are masked out by MAGIC_MASK, so any value there
        // should still match the AIFF magic as long as the ID/formType bytes are correct.
        let buf = BytesMemBuffer(aiff_header(b"AIFF", i32::from_be_bytes([0x7f, 0x11, 0x22, 0x33])));
        assert!(check_magic(&buf, &MAGIC_AIFF));
        assert!(!check_magic(&buf, &MAGIC_AIFC));
    }

    #[test]
    fn value_reads_exact_length_and_reports_type_id() {
        let dt = MockAIFFDataType::new();
        let buf = BytesMemBuffer(vec![1, 2, 3, 4, 5]);
        let value = dt.aiff_value(&buf, &MockSettings, 5).expect("enough bytes");
        assert!(value.downcast_ref::<AudioPlayerImpl>().is_some());
        assert_eq!(
            dt.aiff_value_class(&MockSettings),
            Some(TypeId::of::<AudioPlayerImpl>())
        );
    }

    #[test]
    fn value_is_none_when_not_enough_bytes_available() {
        let dt = MockAIFFDataType::new();
        let buf = BytesMemBuffer(vec![1, 2]);
        assert!(dt.aiff_value(&buf, &MockSettings, 5).is_none());
    }

    #[test]
    fn clone_produces_a_distinct_aiff_data_type() {
        let dt = MockAIFFDataType::new();
        let cloned = dt.aiff_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
        assert_eq!(cloned.aiff_description(), dt.aiff_description());
    }
}
