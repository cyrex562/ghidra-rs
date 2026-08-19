//! Base class for OAT class versions.
//!
//! Port of `ghidra.file.formats.android.oat.oatclass.OatClass`.
//!
//! Java's abstract class carries both state (the parsed status/type fields, the compiled method
//! offsets, and the version-specific status enum) and behaviour (the concrete accessors and the
//! `renameDataType` helper). Following the shared-state split used elsewhere in this crate for
//! abstract Java base classes, the state and concrete methods live in [`OatClassBase`] -- which a
//! concrete `OatClass_*` subclass embeds -- while [`OatClass`] is the trait declaring only the one
//! method Java leaves `abstract`: [`is_method_native`](OatClass::is_method_native).
//!
//! The version-specific status enum families (`OatClassStatusEnum_K`, `_L_M_N`, `_O`, `_O_M2`,
//! `_P_Q`, `_R_S_T`, `_Invalid`) and the sibling `OatClassType` enum and `OatMethodOffsets` class
//! are not ported yet -- see the placeholders in [`crate::file::seam_stubs`].

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::StructConverter;
use crate::file::formats::android::oat::oat_class_status_enum::OatClassStatusEnum;
use crate::file::formats::android::oat::oat_constants::OatConstants;
use crate::file::seam_stubs::{
    OatClassStatusEnumInvalid, OatClassStatusEnumK, OatClassStatusEnumLMN, OatClassStatusEnumO,
    OatClassStatusEnumOM2, OatClassStatusEnumPQ, OatClassStatusEnumRST, OatClassType,
    OatMethodOffsets,
};
use crate::program::model::data::data_type::{DataType, SetDataTypeNameError};

/// The shared state and concrete behaviour of an OAT class.
///
/// Port of the instance fields and non-abstract methods of `OatClass`. Java's fields are
/// `protected`, so a concrete `OatClass_*` subclass reads and writes them directly; this struct
/// makes the same fields `pub` for the same reason.
pub struct OatClassBase {
    /// The OAT version string, used to interpret [`status`](Self::status) against the right
    /// status enum family. Port of the `oatVersion` field.
    pub oat_version: String,
    /// State of the class during compilation. Port of the `status_` field.
    pub status: i16,
    /// The compiled-method encoding used by this class (see [`OatClassType`]). Port of the
    /// `type_` field; unlike `status_`, it is not read by the base constructor -- a concrete
    /// subclass assigns it directly, matching Java.
    pub type_: i16,
    /// Offsets to the generated native code for each compiled method. Port of the
    /// `methods_pointer_` field; empty until a concrete subclass populates it.
    pub methods_pointer: Vec<OatMethodOffsets>,
    /// The status enum instance matching [`status`](Self::status), from the family selected by
    /// [`oat_version`](Self::oat_version). Port of the `statusEnum` field.
    pub status_enum: Box<dyn OatClassStatusEnum>,
}

impl OatClassBase {
    /// Reads the class status and selects the version-appropriate status enum family.
    ///
    /// Port of the protected `OatClass(BinaryReader, String)` constructor.
    pub fn new(reader: &mut dyn BinaryReader, oat_version: &str) -> io::Result<Self> {
        let status = reader.read_next_short()?;

        let status_enum: Box<dyn OatClassStatusEnum> = if oat_version == OatConstants::OAT_VERSION_007 {
            OatClassStatusEnumK::new(0)
                .get(status)
                .unwrap_or_else(|| Box::new(OatClassStatusEnumInvalid::new(status)))
        } else if oat_version == OatConstants::OAT_VERSION_039
            || oat_version == OatConstants::OAT_VERSION_045
            || oat_version == OatConstants::OAT_VERSION_051
            || oat_version == OatConstants::OAT_VERSION_064
            || oat_version == OatConstants::OAT_VERSION_079
            || oat_version == OatConstants::OAT_VERSION_088
        {
            OatClassStatusEnumLMN::new(0)
                .get(status)
                .unwrap_or_else(|| Box::new(OatClassStatusEnumInvalid::new(status)))
        } else if oat_version == OatConstants::OAT_VERSION_124 {
            OatClassStatusEnumO::new(0)
                .get(status)
                .unwrap_or_else(|| Box::new(OatClassStatusEnumInvalid::new(status)))
        } else if oat_version == OatConstants::OAT_VERSION_131 {
            OatClassStatusEnumOM2::new(0)
                .get(status)
                .unwrap_or_else(|| Box::new(OatClassStatusEnumInvalid::new(status)))
        } else if oat_version == OatConstants::OAT_VERSION_138
            || oat_version == OatConstants::OAT_VERSION_170
        {
            OatClassStatusEnumPQ::new(0)
                .get(status)
                .unwrap_or_else(|| Box::new(OatClassStatusEnumInvalid::new(status)))
        } else if oat_version == OatConstants::OAT_VERSION_183
            || oat_version == OatConstants::OAT_VERSION_195
            || oat_version == OatConstants::OAT_VERSION_199
            || oat_version == OatConstants::OAT_VERSION_220
            || oat_version == OatConstants::OAT_VERSION_223
            || oat_version == OatConstants::OAT_VERSION_225
        {
            OatClassStatusEnumRST::new(0)
                .get(status)
                .unwrap_or_else(|| Box::new(OatClassStatusEnumInvalid::new(status)))
        } else {
            Box::new(OatClassStatusEnumInvalid::new(status))
        };

        Ok(OatClassBase {
            oat_version: oat_version.to_string(),
            status,
            type_: 0,
            methods_pointer: Vec::new(),
            status_enum,
        })
    }

    /// State of class during compilation.
    ///
    /// Port of `getStatus()`.
    pub fn get_status(&self) -> i16 {
        self.status
    }

    /// The compiled-method encoding used by this class, or [`OatClassType::KOatClassMax`] if
    /// [`type_`](Self::type_) does not match any known variant.
    ///
    /// Port of `getType()`.
    pub fn get_type(&self) -> OatClassType {
        OatClassType::VALUES
            .into_iter()
            .find(|candidate| candidate.ordinal() == self.type_)
            .unwrap_or(OatClassType::KOatClassMax)
    }

    /// A list of offsets that point to the generated native code for each compiled method.
    ///
    /// Port of `getMethodOffsets()`.
    pub fn get_method_offsets(&self) -> &[OatMethodOffsets] {
        &self.methods_pointer
    }

    /// Renames `data_type` with the specified prefix. The prefix is delimited by the second
    /// underscore character; if fewer than two underscores exist, the entire data type name is
    /// changed to the prefix.
    ///
    /// Port of `renameDataType(DataType, String)`.
    pub fn rename_data_type(
        &self,
        data_type: &mut dyn DataType,
        prefix: &str,
    ) -> Result<(), SetDataTypeNameError> {
        let current_name = data_type.get_name();
        let first_underscore = current_name.find('_');
        let second_underscore = first_underscore
            .and_then(|pos| current_name[pos + 1..].find('_').map(|next| pos + 1 + next));

        match second_underscore {
            None => data_type.set_name(prefix),
            Some(pos) => {
                let new_name = format!("{prefix}{}", &current_name[pos..]);
                data_type.set_name(&new_name)
            }
        }
    }
}

/// The abstract operations of an OAT class that a concrete version must supply.
///
/// Port of the abstract methods of `OatClass`. `OatClass implements StructConverter` in Java but
/// never provides `toDataType()` itself, so that requirement is carried here via the supertrait
/// bound rather than as a method with a body.
pub trait OatClass: StructConverter {
    /// Returns `true` if this method index is declared native in the bitmap.
    ///
    /// Port of `isMethodNative(int)`.
    fn is_method_native(&self, method_index: i32) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::struct_converter::ToDataTypeError;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    struct MockDataType {
        name: String,
    }

    impl MockDataType {
        fn new(name: &str) -> Self {
            MockDataType { name: name.to_string() }
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, name: &str) -> Result<(), SetDataTypeNameError> {
            self.name = name.to_string();
            Ok(())
        }
    }

    struct MockOatClass {
        base: OatClassBase,
    }

    impl StructConverter for MockOatClass {
        fn to_data_type(&self) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, ToDataTypeError> {
            unimplemented!()
        }
    }

    impl OatClass for MockOatClass {
        fn is_method_native(&self, method_index: i32) -> bool {
            method_index == 0
        }
    }

    #[test]
    fn new_reads_status_short_and_stores_oat_version() {
        // 0x0009 little-endian == kStatusInitialized (9) in the KitKat (007) family.
        let mut reader = MockReader::new(vec![0x09, 0x00], true);
        let base = OatClassBase::new(&mut reader, OatConstants::OAT_VERSION_007).unwrap();

        assert_eq!(base.get_status(), 9);
        assert_eq!(base.oat_version, OatConstants::OAT_VERSION_007);
        assert!(base.get_method_offsets().is_empty());
    }

    #[test]
    fn unrecognized_version_falls_back_to_invalid_status_enum() {
        let mut reader = MockReader::new(vec![0x05, 0x00], true);
        let base = OatClassBase::new(&mut reader, "999").unwrap();

        // Falls into the `default` branch of the Java switch, matching `OatClassStatusEnum_Invalid`.
        assert_eq!(base.get_status(), 5);
    }

    #[test]
    fn get_type_matches_ordinal_and_falls_back_to_max() {
        let mut reader = MockReader::new(vec![0x00, 0x00], true);
        let mut base = OatClassBase::new(&mut reader, OatConstants::OAT_VERSION_007).unwrap();

        base.type_ = 1;
        assert_eq!(base.get_type(), OatClassType::KOatClassSomeCompiled);

        base.type_ = 42;
        assert_eq!(base.get_type(), OatClassType::KOatClassMax);
    }

    #[test]
    fn rename_data_type_uses_prefix_when_no_second_underscore() {
        let mut reader = MockReader::new(vec![0x00, 0x00], true);
        let base = OatClassBase::new(&mut reader, OatConstants::OAT_VERSION_007).unwrap();
        let mut dt = MockDataType::new("OatClass_KitKat");

        base.rename_data_type(&mut dt, "prefix").unwrap();
        assert_eq!(dt.get_name(), "prefix");
    }

    #[test]
    fn rename_data_type_keeps_suffix_after_second_underscore() {
        let mut reader = MockReader::new(vec![0x00, 0x00], true);
        let base = OatClassBase::new(&mut reader, OatConstants::OAT_VERSION_007).unwrap();
        let mut dt = MockDataType::new("OatClass_KitKat_1234");

        base.rename_data_type(&mut dt, "prefix").unwrap();
        assert_eq!(dt.get_name(), "prefix_1234");
    }

    #[test]
    fn is_method_native_dispatches_through_trait() {
        let mut reader = MockReader::new(vec![0x00, 0x00], true);
        let base = OatClassBase::new(&mut reader, OatConstants::OAT_VERSION_007).unwrap();
        let oat_class = MockOatClass { base };

        assert!(oat_class.is_method_native(0));
        assert!(!oat_class.is_method_native(1));
    }
}
