//! Port of `ghidra.app.util.bin.format.golang.rtti.GoVarlenString`.

use std::io;
use std::sync::Arc;

use once_cell::sync::Lazy;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::golang::go_ver_range::GoVerRange;
use crate::format::golang::structmapping::structure_mapped::OutputDataType;
use crate::format::golang::structmapping::{DataTypeMapper, StructureContext, StructureMapped, StructureReader};
use crate::format::seam_stubs::GoRttiMapper;
use crate::program::model::data::abstract_integer_data_type::get_unsigned_data_type;
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::unsigned_leb128_data_type::UnsignedLeb128DataType;
use crate::program::seam_stubs::share_data_type;
use crate::util::big_endian_data_converter;

static VERSIONS_THAT_USE_LEB128: Lazy<GoVerRange> = Lazy::new(|| GoVerRange::parse("1.17+"));

/// A pascal-ish string, using a LEB128 (or a big endian uint16 before Go 1.17) value as the
/// length of the following bytes.
///
/// Used mainly in lower-level RTTI structures, this type is a Ghidra'ism used to parse the Go
/// RTTI data and does not have a counterpart in the Go src.
///
/// Java reads the Go version through `context.getDataTypeMapper()` cast to `GoRttiMapper`; here
/// the mapper's published `GoRttiMapper` context value supplies it.
#[derive(StructureMapped, Clone)]
#[structure_mapping(structure_name = "GoVarlenString", reader)]
pub struct GoVarlenString {
    #[context_field]
    context: StructureContext<GoVarlenString>,
    #[context_field]
    program_context: Arc<dyn GoRttiMapper>,
    /// The length of the length field (Java field `strlenLen`, output as `strlen`): the size of
    /// the leb128 / uint16, not its value.
    #[field_output(variable_length, getter = strlen_data_type)]
    strlen: i32,
    /// The string bytes (Java field `bytes`, output as `value`).
    #[field_output(variable_length, getter = value_data_type)]
    value: Vec<u8>,
}

impl GoVarlenString {
    fn use_leb128(&self) -> bool {
        VERSIONS_THAT_USE_LEB128.contains(self.program_context.get_go_ver())
    }

    /// The string's length (`getStrlen()`).
    pub fn get_strlen(&self) -> i32 {
        self.value.len() as i32
    }

    /// The size of the string length field (`getStrlenLen()`).
    pub fn get_strlen_len(&self) -> i32 {
        self.strlen
    }

    /// The raw bytes of the string (`getBytes()`).
    pub fn get_bytes(&self) -> &[u8] {
        &self.value
    }

    /// The string value, decoded as UTF-8 (`getString()`).
    pub fn get_string(&self) -> String {
        String::from_utf8_lossy(&self.value).to_string()
    }

    /// The structure context this string was read with.
    pub fn get_structure_context(&self) -> &StructureContext<GoVarlenString> {
        &self.context
    }

    /// The data type that holds the string length field (`getStrlenDataType()`).
    pub fn strlen_data_type(&self) -> io::Result<OutputDataType> {
        let dt = if self.use_leb128() { UnsignedLeb128DataType::data_type() } else { get_unsigned_data_type(2, None) };
        Ok(OutputDataType::Instance(share_data_type(&dt), self.strlen))
    }

    /// The data type that holds the raw string value (`getValueDataType()`).
    pub fn value_data_type(&self) -> io::Result<OutputDataType> {
        let arr = ArrayDataType::with_element_length(CharDataType::data_type(), self.value.len() as i32, -1)
            .map_err(io::Error::other)?;
        Ok(OutputDataType::DataType(Box::new(arr)))
    }
}

impl StructureReader for GoVarlenString {
    fn read_structure(&mut self, reader: &mut BinaryReader, _mapper: &DataTypeMapper) -> io::Result<()> {
        let start_pos = reader.get_pointer_index();
        let str_len = if self.use_leb128() {
            reader
                .read_next_unsigned_var_int_exact(|r| LEB128Info::unsigned(r).map(|i| i.as_long()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))? as usize
        }
        else {
            reader.read_next_unsigned_short_with(&big_endian_data_converter::INSTANCE)? as usize
        };
        self.strlen = (reader.get_pointer_index() - start_pos) as i32;
        self.value = reader.read_next_byte_array(str_len)?;
        Ok(())
    }
}

impl std::fmt::Display for GoVarlenString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GoVarlenString [context={}, strlenLen={}, bytes={:?}, getString()={}]",
            self.context,
            self.strlen,
            self.value.iter().map(|b| *b as i8).collect::<Vec<_>>(),
            self.get_string()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::go_ver::GoVer;
    use crate::format::golang::rtti::test_support::{go_mapper, try_read_at, Image, VersionOnlyRtti};

    fn mapper(ver: GoVer) -> DataTypeMapper {
        let mut mapper = go_mapper(Arc::new(VersionOnlyRtti(ver)));
        mapper
            .register_structure::<GoVarlenString>(&crate::format::golang::rtti::test_support::go118_tags())
            .expect("register GoVarlenString");
        mapper
    }

    fn image(bytes: &[u8]) -> Image {
        let mut image = Image::default();
        for (i, b) in bytes.iter().enumerate() {
            image.put(i as i64, 1, *b as i64);
        }
        image
    }

    #[test]
    fn reads_leb128_length_go117_plus() {
        let m = mapper(GoVer::new(1, 21, 0));
        let s: GoVarlenString = try_read_at(&m, &image(&[3, b'a', b'b', b'c', 0xff]), 0).unwrap();
        assert_eq!(s.get_string(), "abc");
        assert_eq!(s.get_strlen(), 3);
        assert_eq!(s.get_strlen_len(), 1);
        let dt = s.get_structure_context().get_structure_data_type_for(&s, &m).unwrap();
        // Java: "GoVarlenString" + "_%d" for each variable length field
        assert_eq!(dt.get_name(), "GoVarlenString_1_3");
        assert_eq!(dt.get_length(), 4);
        let comps = dt.as_structure().unwrap().get_defined_components();
        assert_eq!(comps[0].get_field_name().as_deref(), Some("strlen"));
        assert_eq!(comps[0].get_data_type().get_name(), "uleb128");
        assert_eq!(comps[1].get_field_name().as_deref(), Some("value"));

        // a 2 byte leb128 length
        let mut bytes = vec![0x81, 0x01];
        bytes.extend(std::iter::repeat_n(b'x', 129));
        let long: GoVarlenString = try_read_at(&m, &image(&bytes), 0).unwrap();
        assert_eq!(long.get_strlen(), 129);
        assert_eq!(long.get_strlen_len(), 2);
    }

    #[test]
    fn reads_big_endian_u16_length_before_go117() {
        let m = mapper(GoVer::new(1, 16, 0));
        let s: GoVarlenString = try_read_at(&m, &image(&[0, 2, b'h', b'i']), 0).unwrap();
        assert_eq!(s.get_string(), "hi");
        assert_eq!(s.get_strlen_len(), 2);
        let dt = s.get_structure_context().get_structure_data_type_for(&s, &m).unwrap();
        assert_eq!(dt.get_name(), "GoVarlenString_2_2");
        assert_eq!(dt.get_length(), 4);
        assert!(s.to_string().contains("getString()=hi"));
    }

    #[test]
    fn truncated_string_is_an_error() {
        let m = mapper(GoVer::new(1, 21, 0));
        assert!(try_read_at::<GoVarlenString>(&m, &image(&[5, b'a']), 0).is_err());
    }
}
