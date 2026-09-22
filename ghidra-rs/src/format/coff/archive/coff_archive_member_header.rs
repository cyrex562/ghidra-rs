use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::seam_stubs::LongNamesMember;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;
use crate::util::msg::Msg;

const CAMH_NAME_OFF: u64 = 0;
const CAMH_NAME_LEN: usize = 16;

const CAMH_DATE_OFF: u64 = 16;
const CAMH_DATE_LEN: usize = 12;

const CAMH_USERID_OFF: u64 = 28;
const CAMH_USERID_LEN: usize = 6;

const CAMH_GROUPID_OFF: u64 = 34;
const CAMH_GROUPID_LEN: usize = 6;

const CAMH_MODE_OFF: u64 = 40;
const CAMH_MODE_LEN: usize = 8;

const CAMH_SIZE_OFF: u64 = 48;
const CAMH_SIZE_LEN: usize = 10;

const CAMH_EOH_OFF: u64 = 58;
const CAMH_EOH_LEN: usize = 2;
const CAMH_EOH_MAGIC: &str = "`\n";

const CAMH_PAYLOAD_OFF: u64 = 60;
/// Port of `CoffArchiveMemberHeader.CAMH_MIN_SIZE`.
pub const CAMH_MIN_SIZE: u64 = CAMH_PAYLOAD_OFF;

/// Port of `CoffArchiveMemberHeader.SLASH`.
pub const SLASH: &str = "/";
/// Port of `CoffArchiveMemberHeader.SLASH_SLASH`.
pub const SLASH_SLASH: &str = "//";

/// The header of a single member (file) stored inside a COFF archive (`.a`/`.lib`) file.
///
/// Mirrors Ghidra's `ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader`.
pub struct CoffArchiveMemberHeader {
    name: String,
    /// Milliseconds since the Java `Date` epoch (Java field `date`, seconds-since-1970 * 1000).
    date: i64,
    user_id: String,
    group_id: String,
    mode: String,
    size: i64,
    payload_offset: i64,
    member_offset: i64,
}

/// Stand-in for `StructConverter.STRING` (`StringDataType.dataType`), which this crate has not
/// yet ported a concrete singleton for (see `string_data_type.rs`'s module docs). Its `get_name`
/// is the only observable property [`CoffArchiveMemberHeader::to_data_type`] depends on -- the
/// component length used in the resulting structure is supplied explicitly at each `add` call,
/// matching how Java's `add(DataType, length, name, comment)` overload ignores the datatype's own
/// preferred length too. `get_length` only needs to satisfy `Composite`'s "not a zero-length,
/// non-Dynamic datatype" admission check (real `StringDataType` is `Dynamic`, which this minimal
/// stand-in isn't); its value is otherwise unused.
struct StringDt;

impl DataType for StringDt {
    fn get_name(&self) -> String {
        "string".to_string()
    }

    fn get_length(&self) -> i32 {
        1
    }
}

impl CoffArchiveMemberHeader {
    pub fn new(
        name: impl Into<String>,
        date: i64,
        user_id: impl Into<String>,
        group_id: impl Into<String>,
        mode: impl Into<String>,
        size: i64,
        payload_offset: i64,
        member_offset: i64,
    ) -> Self {
        Self {
            name: name.into(),
            date,
            user_id: user_id.into(),
            group_id: group_id.into(),
            mode: mode.into(),
            size,
            payload_offset,
            member_offset,
        }
    }

    /// An archive member header should only start on even byte boundaries. Aligns `reader` if
    /// needed.
    ///
    /// Port of the private `CoffArchiveMemberHeader.align(BinaryReader)`.
    fn align(reader: &mut dyn BinaryReader) {
        if reader.get_pointer_index() % 2 != 0 {
            reader.set_pointer_index(reader.get_pointer_index() + 1);
        }
    }

    /// Reads a COFF archive member header from the specified `reader`, leaving the file position
    /// at the start of this member's payload.
    ///
    /// The archive member's name is fixed up using the specified `long_names` table, when
    /// present.
    ///
    /// Port of `CoffArchiveMemberHeader.read(BinaryReader, LongNamesMember)`.
    pub fn read(reader: &mut dyn BinaryReader, long_names: Option<&dyn LongNamesMember>) -> std::io::Result<Self> {
        Self::align(reader);

        let header_offset = reader.get_pointer_index();

        // Decoding the name field:
        //
        // "/nnn" - a slash followed by an ascii integer string indicates that the actual name
        // is located at offset "nnn" in the "longnames" string table.
        //
        // "#1/nnn" - a "#1/", followed by an ascii integer string indicates that the actual
        // name is located at the beginning of the payload of this member, and its length is
        // 'nnn' bytes. The actual payload starts after the end of the name and its effective
        // size needs to be reduced by the filename length.
        //
        // "name/" - the field gives the name of the archive member directly.
        //
        // "/" - the archive member is one of the two linker members. Both of the linker members
        // have this name.
        //
        // "//" - the archive member is the longname member, which consists of a series of
        // terminated ASCII strings. The longnames member is the third archive member.
        let mut name = reader.read_ascii_string_fixed(header_offset + CAMH_NAME_OFF, CAMH_NAME_LEN)?.trim().to_string();

        // The number of seconds since 1/1/1970 UCT.
        let date_str = reader.read_ascii_string_fixed(header_offset + CAMH_DATE_OFF, CAMH_DATE_LEN)?.trim().to_string();

        // Ascii integer string or blank.
        let user_id = reader.read_ascii_string_fixed(header_offset + CAMH_USERID_OFF, CAMH_USERID_LEN)?.trim().to_string();

        // Ascii integer string or blank.
        let group_id =
            reader.read_ascii_string_fixed(header_offset + CAMH_GROUPID_OFF, CAMH_GROUPID_LEN)?.trim().to_string();

        // Ascii integer string of ST_MODE value from the C run-time function _wstat.
        let mode = reader.read_ascii_string_fixed(header_offset + CAMH_MODE_OFF, CAMH_MODE_LEN)?.trim().to_string();

        // Ascii integer string representing the total size of the archive member, not including
        // the header. If the name is stored at the beginning of the payload (i.e. name ==
        // "#1/nnn"), the member's effective size needs to be adjusted.
        let size_str = reader.read_ascii_string_fixed(header_offset + CAMH_SIZE_OFF, CAMH_SIZE_LEN)?.trim().to_string();

        // Two byte Ascii string 0x60 0x0a ("`\n").
        let end_of_header = reader.read_ascii_string_fixed(header_offset + CAMH_EOH_OFF, CAMH_EOH_LEN)?;
        if end_of_header != CAMH_EOH_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Bad EOH magic string: {end_of_header}"),
            ));
        }

        let mut payload_offset = header_offset + CAMH_PAYLOAD_OFF;

        let mut size: i64 = size_str
            .parse()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Bad size value: {size_str}")))?;

        if let Some(len_str) = name.strip_prefix("#1/") {
            let name_len: usize = len_str
                .parse()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Bad name len value: {name}")))?;
            // name seems to be padded with trailing nulls to put payload at aligned offset
            name = reader.read_ascii_string_fixed(payload_offset, name_len)?;
            size -= name_len as i64;
            payload_offset += name_len as u64;
        }
        else if is_long_name_reference(&name) {
            if let Some(long_names) = long_names {
                let offset: i64 = name[1..].parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Bad long name offset: {name}"))
                })?;
                name = long_names.get_string_at_offset(reader.get_byte_provider(), offset)?;
                if let Some(stripped) = name.strip_suffix('/') {
                    name = stripped.to_string();
                }
            }
        }
        else if name.starts_with('/') {
            // don't do any tweaking of the name, keeps "/" and "//" intact.
        }
        else if let Some(stripped) = name.strip_suffix('/') {
            name = stripped.to_string();
        }

        let mut date: i64 = 0;
        if !date_str.is_empty() {
            match date_str.parse::<i64>() {
                Ok(secs) => date = secs * 1000, // convert from seconds to millis
                Err(_) => {
                    Msg::warn(
                        "CoffArchiveMemberHeader",
                        &format!("COFF Archive: bad date value: [{date_str}] for [{name}] at file offset {header_offset:#x}"),
                    );
                }
            }
        }

        reader.set_pointer_index(payload_offset);

        Ok(Self::new(name, date, user_id, group_id, mode, size, payload_offset as i64, header_offset as i64))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Milliseconds since the Java `Date` epoch.
    pub fn date(&self) -> i64 {
        self.date
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn user_id_int(&self) -> i32 {
        self.user_id.parse().unwrap_or(0)
    }

    pub fn group_id_int(&self) -> i32 {
        self.group_id.parse().unwrap_or(0)
    }

    pub fn mode(&self) -> &str {
        &self.mode
    }

    pub fn size(&self) -> i64 {
        self.size
    }

    pub fn payload_offset(&self) -> i64 {
        self.payload_offset
    }

    pub fn file_offset(&self) -> i64 {
        self.member_offset
    }

    /// Returns true if this header contains a COFF file.
    ///
    /// Port of `CoffArchiveMemberHeader.isCOFF()`.
    pub fn is_coff(&self) -> bool {
        self.name != SLASH && self.name != SLASH_SLASH
    }
}

/// `name.matches("/[0-9]+")`: a slash followed by one or more ascii digits.
fn is_long_name_reference(name: &str) -> bool {
    name.len() > 1 && name.starts_with('/') && name[1..].bytes().all(|b| b.is_ascii_digit())
}

impl StructConverter for CoffArchiveMemberHeader {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut strukt = StructureDataTypeImpl::new("CoffArchiveMemberHeader", 0);
        strukt.add_with_length_and_name(Box::new(StringDt), CAMH_NAME_LEN as i32, Some("name".to_string()), None)?;
        strukt.add_with_length_and_name(Box::new(StringDt), CAMH_DATE_LEN as i32, Some("date".to_string()), None)?;
        strukt.add_with_length_and_name(Box::new(StringDt), CAMH_USERID_LEN as i32, Some("userID".to_string()), None)?;
        strukt.add_with_length_and_name(Box::new(StringDt), CAMH_GROUPID_LEN as i32, Some("groupID".to_string()), None)?;
        strukt.add_with_length_and_name(Box::new(StringDt), CAMH_MODE_LEN as i32, Some("mode".to_string()), None)?;
        strukt.add_with_length_and_name(Box::new(StringDt), CAMH_SIZE_LEN as i32, Some("size".to_string()), None)?;
        strukt.add_with_length_and_name(Box::new(StringDt), CAMH_EOH_LEN as i32, Some("endOfHeader".to_string()), None)?;
        Ok(Box::new(strukt))
    }
}

impl From<String> for ToDataTypeError {
    fn from(e: String) -> Self {
        ToDataTypeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader as _;
    use crate::filesystem::ghidra::g_binary_reader::GByteStore as LegacyByteProvider;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Minimal in-memory `GByteStore`/`BinaryReader` pair for exercising `read()`.
    struct VecByteProvider(Vec<u8>);

    impl LegacyByteProvider for VecByteProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.0.len()
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, index: u64, value: u8) -> std::io::Result<()> {
            self.0[index as usize] = value;
            Ok(())
        }
        fn write_bytes(&mut self, index: u64, values: &[u8]) -> std::io::Result<()> {
            let start = index as usize;
            self.0[start..start + values.len()].copy_from_slice(values);
            Ok(())
        }
    }

    struct SimpleReader {
        provider: Rc<RefCell<dyn LegacyByteProvider>>,
        pointer: u64,
    }

    impl BinaryReader for SimpleReader {
        fn length(&self) -> std::io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _little_endian: bool) {}
        fn get_pointer_index(&self) -> u64 {
            self.pointer
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.pointer;
            self.pointer = index;
            old
        }
        fn read_byte_array(&self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, length)
        }
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn LegacyByteProvider>> {
            self.provider.clone()
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(SimpleReader { provider: self.provider.clone(), pointer: new_index })
        }
    }

    fn pad(s: &str, len: usize) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.resize(len, b' ');
        v
    }

    /// Builds a single, minimal COFF archive member header (no long-name games) with the given
    /// name/date/userid/groupid/mode/size, mirroring the fixed-width ASCII layout Ghidra decodes.
    fn build_header_bytes(name: &str, date: &str, user_id: &str, group_id: &str, mode: &str, size: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(pad(name, CAMH_NAME_LEN));
        v.extend(pad(date, CAMH_DATE_LEN));
        v.extend(pad(user_id, CAMH_USERID_LEN));
        v.extend(pad(group_id, CAMH_GROUPID_LEN));
        v.extend(pad(mode, CAMH_MODE_LEN));
        v.extend(pad(size, CAMH_SIZE_LEN));
        v.extend(CAMH_EOH_MAGIC.as_bytes());
        v
    }

    fn make_reader(bytes: Vec<u8>) -> SimpleReader {
        SimpleReader { provider: Rc::new(RefCell::new(VecByteProvider(bytes))), pointer: 0 }
    }

    #[test]
    fn read_parses_fixed_fields_and_positions_at_payload() {
        let mut bytes = build_header_bytes("foo.o/", "1700000000", "501", "20", "100644", "1234");
        bytes.extend(b"PAYLOAD");
        let mut reader = make_reader(bytes);

        let header = CoffArchiveMemberHeader::read(&mut reader, None).unwrap();
        assert_eq!(header.name(), "foo.o");
        assert_eq!(header.date(), 1_700_000_000_000);
        assert_eq!(header.user_id(), "501");
        assert_eq!(header.group_id(), "20");
        assert_eq!(header.user_id_int(), 501);
        assert_eq!(header.group_id_int(), 20);
        assert_eq!(header.mode(), "100644");
        assert_eq!(header.size(), 1234);
        assert_eq!(header.payload_offset(), CAMH_PAYLOAD_OFF as i64);
        assert_eq!(reader.get_pointer_index(), CAMH_PAYLOAD_OFF);
        assert!(header.is_coff());
    }

    #[test]
    fn read_rejects_bad_eoh_magic() {
        let mut bytes = build_header_bytes("foo.o/", "0", "0", "0", "0", "0");
        // Corrupt the end-of-header magic bytes.
        let eoh_start = CAMH_EOH_OFF as usize;
        bytes[eoh_start] = b'X';
        let mut reader = make_reader(bytes);

        assert!(CoffArchiveMemberHeader::read(&mut reader, None).is_err());
    }

    #[test]
    fn read_handles_hash1_embedded_name() {
        // "#1/8" means an 8-byte name is stored at the start of the payload; the effective
        // member size is reduced by that many bytes.
        let mut bytes = build_header_bytes("#1/8", "0", "0", "0", "0", "20");
        bytes.extend(b"long.o\0\0"); // 8-byte padded embedded name
        bytes.extend(b"restofpayload");
        let mut reader = make_reader(bytes);

        let header = CoffArchiveMemberHeader::read(&mut reader, None).unwrap();
        // `read_ascii_string_fixed` trims trailing NUL padding bytes off the embedded name.
        assert_eq!(header.name(), "long.o");
        assert_eq!(header.size(), 12); // 20 - 8
        assert_eq!(header.payload_offset(), CAMH_PAYLOAD_OFF as i64 + 8);
    }

    #[test]
    fn is_coff_false_for_linker_member_names() {
        let mut bytes = build_header_bytes("/", "0", "0", "0", "0", "0");
        bytes.extend(b"x");
        let mut reader = make_reader(bytes);
        let header = CoffArchiveMemberHeader::read(&mut reader, None).unwrap();
        assert!(!header.is_coff());
    }

    #[test]
    fn is_coff_false_for_longnames_member() {
        let mut bytes = build_header_bytes("//", "0", "0", "0", "0", "0");
        bytes.extend(b"x");
        let mut reader = make_reader(bytes);
        let header = CoffArchiveMemberHeader::read(&mut reader, None).unwrap();
        assert!(!header.is_coff());
    }

    #[test]
    fn to_data_type_produces_seven_field_structure() {
        let header = CoffArchiveMemberHeader::new("foo.o", 0, "0", "0", "0", 0, 0, 0);
        let dt = header.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "CoffArchiveMemberHeader");
    }

    struct MockLongNames {
        table: Vec<(i64, String)>,
    }

    impl LongNamesMember for MockLongNames {
        fn get_string_at_offset(
            &self,
            _provider: Rc<RefCell<dyn LegacyByteProvider>>,
            offset: i64,
        ) -> std::io::Result<String> {
            self.table
                .iter()
                .find(|(o, _)| *o == offset)
                .map(|(_, s)| s.clone())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such offset"))
        }
    }

    #[test]
    fn read_resolves_long_name_via_longnames_table() {
        let mut bytes = build_header_bytes("/4", "0", "0", "0", "0", "3");
        bytes.extend(b"abc");
        let mut reader = make_reader(bytes);
        let long_names = MockLongNames { table: vec![(4, "really_long_name.o/".to_string())] };

        let header = CoffArchiveMemberHeader::read(&mut reader, Some(&long_names)).unwrap();
        assert_eq!(header.name(), "really_long_name.o");
    }
}
