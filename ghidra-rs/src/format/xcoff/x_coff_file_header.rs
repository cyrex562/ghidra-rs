//! Port of `ghidra.app.util.bin.format.xcoff.XCoffFileHeader`.

use std::cell::RefCell;
use std::fmt;
use std::io;
use std::rc::Rc;

use thiserror::Error;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::format::coff::coff_file_header::CoffBinaryReader;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

use super::x_coff_exception::XCoffException;
use super::x_coff_file_header_magic;
use super::x_coff_optional_header::XCoffOptionalHeader;

/// Size of the fixed part of the XCOFF file header that must be present, in bytes.
pub const SIZEOF: u64 = 20;

/// Error produced while reading an [`XCoffFileHeader`]; stands in for the two checked exceptions
/// the Java constructor declares (`IOException`, `XCoffException`).
#[derive(Debug, Error)]
pub enum XCoffFileHeaderError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    XCoff(#[from] XCoffException),
}

/// XCOFF file header. Handles both the 32- and 64-bit cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XCoffFileHeader {
    f_magic: i16,
    f_nscns: i16,
    f_timdat: i32,
    f_symptr: i64,
    f_nsyms: i32,
    f_opthdr: i16,
    f_flags: i16,
    optional_header: Option<XCoffOptionalHeader>,
}

impl XCoffFileHeader {
    /// Reads the header from the start of `provider`, always big endian.
    ///
    /// Port of `XCoffFileHeader(ByteProvider)`. Fails with an [`XCoffException`] if the provider
    /// is shorter than [`SIZEOF`] bytes, the magic number is not an XCOFF magic, or the magic is
    /// neither 32- nor 64-bit.
    pub fn new(provider: Rc<RefCell<dyn GByteStore>>) -> Result<Self, XCoffFileHeaderError> {
        if provider.borrow_mut().length()? < SIZEOF {
            return Err(XCoffException::new("Invalid XCOFF: file is too small.").into());
        }
        let mut reader = CoffBinaryReader::new(provider, false /* always big endian */);
        Self::read(&mut reader)
    }

    /// Reads the header at the reader's current position; the reader must be big endian.
    fn read(reader: &mut dyn BinaryReader) -> Result<Self, XCoffFileHeaderError> {
        if !x_coff_file_header_magic::is_match(reader.peek_next_short()? as u16) {
            return Err(XCoffException::new("Invalid XCOFF: incorrect magic value.").into());
        }

        let f_magic = reader.read_next_short()?;
        let f_nscns = reader.read_next_short()?;
        let f_timdat = reader.read_next_int()?;
        let f_symptr = if x_coff_file_header_magic::is_32bit(f_magic as u16) {
            reader.read_next_unsigned_int()? as i64
        } else if x_coff_file_header_magic::is_64bit(f_magic as u16) {
            reader.read_next_long()?
        } else {
            return Err(XCoffException::new("Invalid XCOFF: unrecognized bit size.").into());
        };
        let f_nsyms = reader.read_next_int()?;
        let f_opthdr = reader.read_next_short()?;
        let f_flags = reader.read_next_short()?;

        let optional_header =
            if f_opthdr > 0 { Some(XCoffOptionalHeader::new(reader, f_magic)?) } else { None };

        Ok(Self { f_magic, f_nscns, f_timdat, f_symptr, f_nsyms, f_opthdr, f_flags, optional_header })
    }

    /// Magic number.
    pub fn get_magic(&self) -> i16 {
        self.f_magic
    }

    /// Number of sections.
    pub fn get_section_count(&self) -> i16 {
        self.f_nscns
    }

    /// Time and date stamp.
    pub fn get_time_stamp(&self) -> i32 {
        self.f_timdat
    }

    /// File pointer to the symbol table.
    pub fn get_symbol_table_pointer(&self) -> i64 {
        self.f_symptr
    }

    /// Number of symbol table entries.
    pub fn get_symbol_table_entries(&self) -> i32 {
        self.f_nsyms
    }

    /// Size of the optional header.
    pub fn get_optional_header_size(&self) -> i16 {
        self.f_opthdr
    }

    /// Flags.
    pub fn get_flags(&self) -> i16 {
        self.f_flags
    }

    /// The optional header, or `None` (Java `null`) when [`get_optional_header_size`] is not
    /// positive.
    ///
    /// [`get_optional_header_size`]: Self::get_optional_header_size
    pub fn get_optional_header(&self) -> Option<&XCoffOptionalHeader> {
        self.optional_header.as_ref()
    }
}

impl fmt::Display for XCoffFileHeader {
    /// Port of `toString()`. Java formats `f_timdat` with `DateFormat.getDateInstance()` on
    /// `new Date(f_timdat)` -- i.e. treating the stamp as *milliseconds* since the epoch -- in the
    /// default locale and time zone; this uses the `en_US` medium form (`Jan 1, 1970`) in UTC.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "FILE HEADER VALUES")?;
        writeln!(f, "f_magic  = {}", self.f_magic)?;
        writeln!(f, "f_nscns  = {}", self.f_nscns)?;
        writeln!(f, "f_timdat = {}", medium_date_utc(self.f_timdat as i64))?;
        writeln!(f, "f_symptr = {}", self.f_symptr)?;
        writeln!(f, "f_nsyms  = {}", self.f_nsyms)?;
        writeln!(f, "f_opthdr = {}", self.f_opthdr)?;
        writeln!(f, "f_flags  = {}", self.f_flags)
    }
}

impl StructConverter for XCoffFileHeader {
    /// Port of `toDataType()`, which delegates to `StructConverterUtil.toDataType`: one component
    /// per non-static private field, skipping `_optionalHeader` (leading underscore).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut s = StructureDataTypeImpl::new("XCoffFileHeader", 0);
        for (dt, name) in [
            (PrimitiveDt::WORD, "f_magic"),
            (PrimitiveDt::WORD, "f_nscns"),
            (PrimitiveDt::DWORD, "f_timdat"),
            (PrimitiveDt::QWORD, "f_symptr"),
            (PrimitiveDt::DWORD, "f_nsyms"),
            (PrimitiveDt::WORD, "f_opthdr"),
            (PrimitiveDt::WORD, "f_flags"),
        ] {
            s.add_with_name(dt.boxed(), Some(name.to_string()), None)?;
        }
        Ok(Box::new(s))
    }
}

/// Formats epoch milliseconds as the `en_US` medium date (`MMM d, yyyy`) in UTC.
fn medium_date_utc(millis: i64) -> String {
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    // Civil-from-days (proleptic Gregorian), after Howard Hinnant's algorithm.
    let z = millis.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{} {}, {}", MONTHS[(month - 1) as usize], day, year)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::seam_stubs::ByteArrayProvider;
    use crate::format::xcoff::x_coff_file_header_magic::{MAGIC_XCOFF32, MAGIC_XCOFF64};

    fn provider(bytes: Vec<u8>) -> Rc<RefCell<dyn GByteStore>> {
        Rc::new(RefCell::new(ByteArrayProvider::new(bytes)))
    }

    fn header32(opthdr: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(MAGIC_XCOFF32.to_be_bytes());
        b.extend(4u16.to_be_bytes()); // f_nscns
        b.extend(0x1234_5678u32.to_be_bytes()); // f_timdat
        b.extend(0x8000_0010u32.to_be_bytes()); // f_symptr (zero-extended)
        b.extend(42u32.to_be_bytes()); // f_nsyms
        b.extend(opthdr.to_be_bytes()); // f_opthdr
        b.extend(0x1002u16.to_be_bytes()); // f_flags
        b
    }

    #[test]
    fn reads_32bit_header_without_optional_header() {
        let h = XCoffFileHeader::new(provider(header32(0))).unwrap();
        assert_eq!(h.get_magic(), 0x01df);
        assert_eq!(h.get_section_count(), 4);
        assert_eq!(h.get_time_stamp(), 0x1234_5678);
        assert_eq!(h.get_symbol_table_pointer(), 0x8000_0010);
        assert_eq!(h.get_symbol_table_entries(), 42);
        assert_eq!(h.get_optional_header_size(), 0);
        assert_eq!(h.get_flags(), 0x1002);
        assert!(h.get_optional_header().is_none());
    }

    #[test]
    fn reads_optional_header_when_size_is_positive() {
        let mut b = header32(72);
        b.extend(0x010bu16.to_be_bytes()); // o_magic
        b.extend(1u16.to_be_bytes()); // o_vstamp
        b.extend([0u8; 28]); // tsize..toc
        b.extend([0u8; 16]); // section numbers + alignments
        b.extend(*b"1L");
        b.extend([0u8; 2 + 12 + 1 + 4]);
        let h = XCoffFileHeader::new(provider(b)).unwrap();
        let opt = h.get_optional_header().expect("optional header");
        assert_eq!(opt.get_magic(), 0x010b);
        assert_eq!(opt.get_version_stamp(), 1);
        assert_eq!(opt.get_module_type(), "1L");
    }

    #[test]
    fn reads_64bit_symbol_pointer() {
        let mut b = Vec::new();
        b.extend(MAGIC_XCOFF64.to_be_bytes());
        b.extend(1u16.to_be_bytes());
        b.extend(0u32.to_be_bytes());
        b.extend(0x0000_0001_0000_0000u64.to_be_bytes());
        b.extend(7u32.to_be_bytes());
        b.extend(0u16.to_be_bytes());
        b.extend(0u16.to_be_bytes());
        let h = XCoffFileHeader::new(provider(b)).unwrap();
        assert_eq!(h.get_magic() as u16, MAGIC_XCOFF64);
        assert_eq!(h.get_symbol_table_pointer(), 0x1_0000_0000);
        assert_eq!(h.get_symbol_table_entries(), 7);
    }

    #[test]
    fn rejects_short_input() {
        let err = XCoffFileHeader::new(provider(vec![0x01, 0xdf, 0, 0])).unwrap_err();
        assert_eq!(err.to_string(), "Invalid XCOFF: file is too small.");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = header32(0);
        b[0] = 0x7f;
        let err = XCoffFileHeader::new(provider(b)).unwrap_err();
        assert_eq!(err.to_string(), "Invalid XCOFF: incorrect magic value.");
    }

    #[test]
    fn truncated_64bit_header_is_an_io_error() {
        // 20 bytes passes the size check but the 64-bit layout needs 24.
        let mut b = Vec::new();
        b.extend(MAGIC_XCOFF64.to_be_bytes());
        b.extend([0u8; 18]);
        assert!(matches!(XCoffFileHeader::new(provider(b)), Err(XCoffFileHeaderError::Io(_))));
    }

    #[test]
    fn display_matches_java_layout() {
        let h = XCoffFileHeader::new(provider(header32(0))).unwrap();
        // 0x12345678 ms after the epoch is 1970-01-04 (305419896 ms ~= 3.5 days).
        assert_eq!(
            h.to_string(),
            "FILE HEADER VALUES\nf_magic  = 479\nf_nscns  = 4\nf_timdat = Jan 4, 1970\n\
             f_symptr = 2147483664\nf_nsyms  = 42\nf_opthdr = 0\nf_flags  = 4098\n"
        );
    }

    #[test]
    fn medium_date_handles_pre_epoch_values() {
        assert_eq!(medium_date_utc(0), "Jan 1, 1970");
        assert_eq!(medium_date_utc(-1), "Dec 31, 1969");
        assert_eq!(medium_date_utc(i32::MIN as i64), "Dec 7, 1969");
        assert_eq!(medium_date_utc(i32::MAX as i64), "Jan 25, 1970");
    }

    #[test]
    fn to_data_type_lists_fields_without_optional_header() {
        let h = XCoffFileHeader::new(provider(header32(0))).unwrap();
        let dt = h.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "XCoffFileHeader");
        assert_eq!(dt.get_length(), 2 + 2 + 4 + 8 + 4 + 2 + 2);
    }
}
