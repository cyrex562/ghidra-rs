//! Port of `ghidra.app.util.bin.format.xcoff.XCoffOptionalHeader`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::program::model::data::data_type::DataType;

use super::x_coff_file_header_magic;

/// Size of the XCOFF auxiliary ("a.out") header in bytes. The first 28 bytes are the same as
/// for COFF.
pub const AOUTHDRSZ: i32 = 72;

/// The XCOFF optional (auxiliary) header. Handles both the 32- and 64-bit layouts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XCoffOptionalHeader {
    o_magic: i16,
    o_vstamp: i16,
    o_tsize: i64,
    o_dsize: i64,
    o_bsize: i64,
    o_entry: i64,
    o_text_start: i64,
    o_data_start: i64,
    o_toc: i64,
    o_snentry: i16,
    o_sntext: i16,
    o_sndata: i16,
    o_sntoc: i16,
    o_snloader: i16,
    o_snbss: i16,
    o_algntext: i16,
    o_algndata: i16,
    o_modtype: Vec<u8>,
    o_cpuflag: u8,
    o_cputype: u8,
    o_maxstack: i64,
    o_maxdata: i64,
    o_debugger: i64,
    o_flags: u8,
    o_sntdata: i16,
    o_sntbss: i16,
}

impl XCoffOptionalHeader {
    /// Reads the optional header at the reader's current position.
    ///
    /// Port of the package-private `XCoffOptionalHeader(BinaryReader, XCoffFileHeader)`
    /// constructor. Java only consults the file header for its magic number (via
    /// `XCoffFileHeaderMagic.is32bit/is64bit`) -- and does so while the file header is still
    /// being constructed -- so the magic is passed directly. For a magic that is neither 32- nor
    /// 64-bit the size-dependent fields are left `0`, as in Java.
    pub(crate) fn new(reader: &mut dyn BinaryReader, file_header_magic: i16) -> io::Result<Self> {
        let magic = file_header_magic as u16;
        let is32 = x_coff_file_header_magic::is_32bit(magic);
        let is64 = x_coff_file_header_magic::is_64bit(magic);

        let o_magic = reader.read_next_short()?;
        let o_vstamp = reader.read_next_short()?;

        let mut sized = [0i64; 7];
        if is32 {
            for v in sized.iter_mut() {
                *v = reader.read_next_unsigned_int()? as i64;
            }
        } else if is64 {
            for v in sized.iter_mut() {
                *v = reader.read_next_long()?;
            }
        }
        let [o_tsize, o_dsize, o_bsize, o_entry, o_text_start, o_data_start, o_toc] = sized;

        let o_snentry = reader.read_next_short()?;
        let o_sntext = reader.read_next_short()?;
        let o_sndata = reader.read_next_short()?;
        let o_sntoc = reader.read_next_short()?;
        let o_snloader = reader.read_next_short()?;
        let o_snbss = reader.read_next_short()?;
        let o_algntext = reader.read_next_short()?;
        let o_algndata = reader.read_next_short()?;
        let o_modtype = reader.read_next_byte_array(2)?;
        let o_cpuflag = reader.read_next_byte()?;
        let o_cputype = reader.read_next_byte()?;

        let mut limits = [0i64; 3];
        if is32 {
            for v in limits.iter_mut() {
                *v = reader.read_next_unsigned_int()? as i64;
            }
        } else if is64 {
            for v in limits.iter_mut() {
                *v = reader.read_next_long()?;
            }
        }
        let [o_maxstack, o_maxdata, o_debugger] = limits;

        let o_flags = reader.read_next_byte()?;
        let o_sntdata = reader.read_next_short()?;
        let o_sntbss = reader.read_next_short()?;

        Ok(Self {
            o_magic,
            o_vstamp,
            o_tsize,
            o_dsize,
            o_bsize,
            o_entry,
            o_text_start,
            o_data_start,
            o_toc,
            o_snentry,
            o_sntext,
            o_sndata,
            o_sntoc,
            o_snloader,
            o_snbss,
            o_algntext,
            o_algndata,
            o_modtype,
            o_cpuflag,
            o_cputype,
            o_maxstack,
            o_maxdata,
            o_debugger,
            o_flags,
            o_sntdata,
            o_sntbss,
        })
    }

    /// Type of file (conventionally `0x010B`).
    pub fn get_magic(&self) -> i16 {
        self.o_magic
    }
    /// Version stamp (conventionally `1`).
    pub fn get_version_stamp(&self) -> i16 {
        self.o_vstamp
    }
    /// Text size in bytes, padded to a full-word boundary.
    pub fn get_text_size(&self) -> i64 {
        self.o_tsize
    }
    /// Initialized data size in bytes.
    pub fn get_initialized_data_size(&self) -> i64 {
        self.o_dsize
    }
    /// Uninitialized data size in bytes.
    pub fn get_uninitialized_data_size(&self) -> i64 {
        self.o_bsize
    }
    /// Entry point.
    pub fn get_entry(&self) -> i64 {
        self.o_entry
    }
    /// Base of text used for this file.
    pub fn get_text_start(&self) -> i64 {
        self.o_text_start
    }
    /// Base of data used for this file.
    pub fn get_data_start(&self) -> i64 {
        self.o_data_start
    }
    /// Address of the TOC anchor (`getTOC()`).
    pub fn get_toc(&self) -> i64 {
        self.o_toc
    }
    /// Section number for the entry point.
    pub fn get_section_number_for_entry(&self) -> i16 {
        self.o_snentry
    }
    /// Section number for `.text`.
    pub fn get_section_number_for_text(&self) -> i16 {
        self.o_sntext
    }
    /// Section number for `.data`.
    pub fn get_section_number_for_data(&self) -> i16 {
        self.o_sndata
    }
    /// Section number for the TOC.
    pub fn get_section_number_for_toc(&self) -> i16 {
        self.o_sntoc
    }
    /// Section number for loader data.
    pub fn get_section_number_for_loader(&self) -> i16 {
        self.o_snloader
    }
    /// Section number for `.bss`.
    pub fn get_section_number_for_bss(&self) -> i16 {
        self.o_snbss
    }
    /// Maximum alignment for `.text`.
    pub fn get_max_alignment_for_text(&self) -> i16 {
        self.o_algntext
    }
    /// Maximum alignment for `.data`.
    pub fn get_max_alignment_for_data(&self) -> i16 {
        self.o_algndata
    }
    /// The two-character module type field (e.g. `"1L"`, `"RO"`).
    pub fn get_module_type(&self) -> String {
        String::from_utf8_lossy(&self.o_modtype).into_owned()
    }
    /// Bit flags -- CPU types of objects.
    pub fn get_cpu_flag(&self) -> u8 {
        self.o_cpuflag
    }
    /// Reserved for CPU type.
    pub fn get_cpu_type(&self) -> u8 {
        self.o_cputype
    }
    /// Maximum stack size allowed, in bytes.
    pub fn get_max_stack_size(&self) -> i64 {
        self.o_maxstack
    }
    /// Maximum data size allowed, in bytes.
    pub fn get_max_data_size(&self) -> i64 {
        self.o_maxdata
    }
    /// Reserved for debuggers.
    pub fn get_debugger(&self) -> i64 {
        self.o_debugger
    }
    /// Flags and thread-local storage alignment.
    pub fn get_flags(&self) -> u8 {
        self.o_flags
    }
    /// Section number for `.tdata`.
    pub fn get_section_number_for_t_data(&self) -> i16 {
        self.o_sntdata
    }
    /// Section number for `.tbss`.
    pub fn get_section_number_for_t_bss(&self) -> i16 {
        self.o_sntbss
    }
}

impl fmt::Display for XCoffOptionalHeader {
    /// Port of `toString()`. Java appends the raw `byte[]` for `o_modtype` (printing an
    /// identity hash such as `[B@1b6d3586`, which cannot be reproduced); the module type string
    /// is printed instead. Java prints `byte` fields signed, so `o_cpuflag`/`o_cputype`/`o_flags`
    /// are shown as `i8`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "OPTIONAL HEADER VALUES")?;
        writeln!(f, "magic      = {}", self.o_magic)?;
        writeln!(f, "vstamp     = {}", self.o_vstamp)?;
        writeln!(f, "tsize      = {}", self.o_tsize)?;
        writeln!(f, "dsize      = {}", self.o_dsize)?;
        writeln!(f, "bsize      = {}", self.o_bsize)?;
        writeln!(f, "entry      = {}", self.o_entry)?;
        writeln!(f, "text_start = {}", self.o_text_start)?;
        writeln!(f, "data_start = {}", self.o_data_start)?;
        writeln!(f, "o_toc      = {}", self.o_toc)?;
        writeln!(f, "o_snentry  = {}", self.o_snentry)?;
        writeln!(f, "o_sntext   = {}", self.o_sntext)?;
        writeln!(f, "o_sndata   = {}", self.o_sndata)?;
        writeln!(f, "o_sntoc    = {}", self.o_sntoc)?;
        writeln!(f, "o_snloader = {}", self.o_snloader)?;
        writeln!(f, "o_snbss    = {}", self.o_snbss)?;
        writeln!(f, "o_algntext = {}", self.o_algntext)?;
        writeln!(f, "o_algndata = {}", self.o_algndata)?;
        writeln!(f, "o_modtype  = {}", self.get_module_type())?;
        writeln!(f, "o_cpuflag  = {}", self.o_cpuflag as i8)?;
        writeln!(f, "o_cputype  = {}", self.o_cputype as i8)?;
        writeln!(f, "o_maxstack = {}", self.o_maxstack)?;
        writeln!(f, "o_maxdata  = {}", self.o_maxdata)?;
        writeln!(f, "o_flags    = {}", self.o_flags as i8)?;
        writeln!(f, "o_debugger = {}", self.o_debugger)?;
        writeln!(f, "o_sntdata  = {}", self.o_sntdata)?;
        writeln!(f, "o_sntbss   = {}", self.o_sntbss)
    }
}

impl StructConverter for XCoffOptionalHeader {
    /// Port of `toDataType()`, which calls `StructConverterUtil.toDataType(XCoffOptionalHeader.class)`.
    ///
    /// That class-based overload reflects with a `null` instance, and the `byte[] o_modtype`
    /// field makes `StructConverterUtil.getArrayDataType` read the array length off that `null`
    /// instance, so the Java method always fails (a `RuntimeException` wrapping a
    /// `NullPointerException`). The same failure is reported here as an error.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::other(
            "XCoffOptionalHeader: automatic structure conversion cannot size array field o_modtype",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::VecReader;
    use crate::format::xcoff::x_coff_file_header_magic::{MAGIC_XCOFF32, MAGIC_XCOFF64};

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    /// Builds the 69 bytes the Java constructor reads for a 32-bit auxiliary header.
    fn aout32() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(be16(0x010b)); // o_magic
        b.extend(be16(1)); // o_vstamp
        for v in [0x1000u32, 0x200, 0x30, 0x1000_0128, 0x1000_0000, 0x2000_0000, 0xf000_0000] {
            b.extend(v.to_be_bytes());
        }
        for v in [2u16, 1, 2, 2, 4, 3, 7, 3] {
            b.extend(be16(v));
        }
        b.extend(*b"1L"); // o_modtype
        b.push(0x80); // o_cpuflag
        b.push(0x02); // o_cputype
        for v in [0x0010_0000u32, 0x0020_0000, 0] {
            b.extend(v.to_be_bytes());
        }
        b.push(0x05); // o_flags
        b.extend(be16(5)); // o_sntdata
        b.extend(be16(6)); // o_sntbss
        b
    }

    #[test]
    fn reads_32bit_layout() {
        let data = aout32();
        assert_eq!(data.len(), 69);
        let mut reader = VecReader::new(data);
        let h = XCoffOptionalHeader::new(&mut reader, MAGIC_XCOFF32 as i16).unwrap();
        assert_eq!(reader.get_pointer_index(), 69);
        assert_eq!(h.get_magic(), 0x010b);
        assert_eq!(h.get_version_stamp(), 1);
        assert_eq!(h.get_text_size(), 0x1000);
        assert_eq!(h.get_initialized_data_size(), 0x200);
        assert_eq!(h.get_uninitialized_data_size(), 0x30);
        assert_eq!(h.get_entry(), 0x1000_0128);
        assert_eq!(h.get_text_start(), 0x1000_0000);
        assert_eq!(h.get_data_start(), 0x2000_0000);
        // 32-bit values are zero-extended (`readNextInt() & 0xffffffffL`).
        assert_eq!(h.get_toc(), 0xf000_0000);
        assert_eq!(h.get_section_number_for_entry(), 2);
        assert_eq!(h.get_section_number_for_text(), 1);
        assert_eq!(h.get_section_number_for_data(), 2);
        assert_eq!(h.get_section_number_for_toc(), 2);
        assert_eq!(h.get_section_number_for_loader(), 4);
        assert_eq!(h.get_section_number_for_bss(), 3);
        assert_eq!(h.get_max_alignment_for_text(), 7);
        assert_eq!(h.get_max_alignment_for_data(), 3);
        assert_eq!(h.get_module_type(), "1L");
        assert_eq!(h.get_cpu_flag(), 0x80);
        assert_eq!(h.get_cpu_type(), 0x02);
        assert_eq!(h.get_max_stack_size(), 0x0010_0000);
        assert_eq!(h.get_max_data_size(), 0x0020_0000);
        assert_eq!(h.get_debugger(), 0);
        assert_eq!(h.get_flags(), 5);
        assert_eq!(h.get_section_number_for_t_data(), 5);
        assert_eq!(h.get_section_number_for_t_bss(), 6);
    }

    #[test]
    fn reads_64bit_layout() {
        let mut b = Vec::new();
        b.extend(be16(0x010b));
        b.extend(be16(1));
        for v in 1u64..=7 {
            b.extend((v << 32 | v).to_be_bytes());
        }
        for v in 1u16..=8 {
            b.extend(be16(v));
        }
        b.extend(*b"RO");
        b.push(0);
        b.push(0);
        for v in [0xffff_ffff_ffff_fff0u64, 0x10, 0x20] {
            b.extend(v.to_be_bytes());
        }
        b.push(0xff);
        b.extend(be16(9));
        b.extend(be16(10));
        let len = b.len() as u64;

        let mut reader = VecReader::new(b);
        let h = XCoffOptionalHeader::new(&mut reader, MAGIC_XCOFF64 as i16).unwrap();
        assert_eq!(reader.get_pointer_index(), len);
        assert_eq!(h.get_text_size(), 0x1_0000_0001);
        assert_eq!(h.get_toc(), 0x7_0000_0007);
        assert_eq!(h.get_section_number_for_entry(), 1);
        assert_eq!(h.get_max_alignment_for_data(), 8);
        assert_eq!(h.get_module_type(), "RO");
        assert_eq!(h.get_max_stack_size(), -16);
        assert_eq!(h.get_max_data_size(), 0x10);
        assert_eq!(h.get_debugger(), 0x20);
        assert_eq!(h.get_flags(), 0xff);
        assert_eq!(h.get_section_number_for_t_bss(), 10);
        assert!(h.to_string().contains("o_flags    = -1\n"));
    }

    #[test]
    fn truncated_input_is_an_error() {
        let mut data = aout32();
        data.truncate(40);
        assert!(XCoffOptionalHeader::new(&mut VecReader::new(data), MAGIC_XCOFF32 as i16).is_err());
    }

    #[test]
    fn display_matches_java_layout() {
        let h = XCoffOptionalHeader::new(&mut VecReader::new(aout32()), MAGIC_XCOFF32 as i16).unwrap();
        let s = h.to_string();
        assert!(s.starts_with("OPTIONAL HEADER VALUES\nmagic      = 267\nvstamp     = 1\n"));
        assert!(s.contains("o_modtype  = 1L\n"));
        assert!(s.contains("o_cpuflag  = -128\n"));
        assert!(s.ends_with("o_sntdata  = 5\no_sntbss   = 6\n"));
    }

    #[test]
    fn to_data_type_fails_like_java() {
        let h = XCoffOptionalHeader::new(&mut VecReader::new(aout32()), MAGIC_XCOFF32 as i16).unwrap();
        assert!(h.to_data_type().is_err());
    }
}
