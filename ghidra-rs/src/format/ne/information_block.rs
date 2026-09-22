use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::invalid_windows_header_exception::InvalidWindowsHeaderException;
use crate::format::ne::windows_header::WindowsHeader;
use std::io;

const TAB: &str = "        ";

/// Represents the Information Block defined in the Windows new-style executable.
///
/// ...as defined in WINNT.H
///
/// ```text
/// typedef struct _IMAGE_OS2_HEADER {      // OS/2 .EXE header
///     WORD   ne_magic;                    // Magic number
///     CHAR   ne_ver;                      // Version number
///     CHAR   ne_rev;                      // Revision number
///     WORD   ne_enttab;                   // Offset of Entry Table
///     WORD   ne_cbenttab;                 // Number of bytes in Entry Table
///     LONG   ne_crc;                      // Checksum of whole file
///     WORD   ne_flags;                    // Flag word
///     WORD   ne_autodata;                 // Automatic data segment number
///     WORD   ne_heap;                     // Initial heap allocation
///     WORD   ne_stack;                    // Initial stack allocation
///     LONG   ne_csip;                     // Initial CS:IP setting
///     LONG   ne_sssp;                     // Initial SS:SP setting
///     WORD   ne_cseg;                     // Count of file segments
///     WORD   ne_cmod;                     // Entries in Module Reference Table
///     WORD   ne_cbnrestab;                // Size of non-resident name table
///     WORD   ne_segtab;                   // Offset of Segment Table
///     WORD   ne_rsrctab;                  // Offset of Resource Table
///     WORD   ne_restab;                   // Offset of resident name table
///     WORD   ne_modtab;                   // Offset of Module Reference Table
///     WORD   ne_imptab;                   // Offset of Imported Names Table
///     LONG   ne_nrestab;                  // Offset of Non-resident Names Table
///     WORD   ne_cmovent;                  // Count of movable entries
///     WORD   ne_align;                    // Segment alignment shift count
///     WORD   ne_cres;                     // Count of resource segments
///     BYTE   ne_exetyp;                   // Target Operating system
///     BYTE   ne_flagsothers;              // Other .EXE flags
///     WORD   ne_pretthunks;               // offset to return thunks
///     WORD   ne_psegrefbytes;             // offset to segment ref. bytes
///     WORD   ne_swaparea;                 // Minimum code swap area size
///     WORD   ne_expver;                   // Expected Windows version number
/// } IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;
/// ```
///
/// Mirrors `InformationBlock` from the original Ghidra Java source.
#[derive(Debug, Clone)]
pub struct InformationBlock {
    ne_magic: i16,        // Magic number
    ne_ver: i8,           // Version number
    ne_rev: i8,           // Revision number
    ne_enttab: i16,       // Offset of entry table
    ne_cbenttab: i16,     // Number of bytes in entry table
    ne_crc: i32,          // Checksum of whole file
    ne_flags_prog: i8,    // Flag word - program
    ne_flags_app: i8,     // Flag word - application
    ne_autodata: i16,     // Automatic data segment number
    ne_heap: i16,         // Initial heap allocation
    ne_stack: i16,        // Initial stack allocation
    ne_csip: i32,         // Initial CS:IP setting
    ne_sssp: i32,         // Initial SS:SP setting
    ne_cseg: i16,         // Count of file segments
    ne_cmod: i16,         // Entries in module reference table
    ne_cbnrestab: i16,    // Size of non-resident name table
    ne_segtab: i16,       // Offset of segment table
    ne_rsrctab: i16,      // Offset of resource table
    ne_restab: i16,       // Offset of resident name table
    ne_modtab: i16,       // Offset of module reference table
    ne_imptab: i16,       // Offset of imported names table
    ne_nrestab: i32,      // Offset of non-resident names table
    ne_cmovent: i16,      // Count of movable entries
    ne_align: i16,        // Segment alignment shift count
    ne_cres: i16,         // Count of resource segments
    ne_exetyp: i8,        // Target operating system
    ne_flagsothers: i8,   // Other .EXE flags
    ne_pretthunks: i16,   // offset to return thunks
    ne_psegrefbytes: i16, // offset to segment ref. bytes
    ne_swaparea: i16,     // Minimum code swap area size
    ne_expver: i16,       // Expected windows version number
}

impl InformationBlock {
    /// Program flags: no auto data segments.
    pub const FLAGS_PROG_NO_AUTO_DATA: i8 = 0x00;
    /// Program flags: single data segment.
    pub const FLAGS_PROG_SINGLE_DATA: i8 = 0x01;
    /// Program flags: multiple data segments.
    pub const FLAGS_PROG_MULTIPLE_DATA: i8 = 0x02;

    pub const FLAGS_PROG_GLOBAL_INIT: i8 = 0x04;
    pub const FLAGS_PROG_PROTECTED_MODE: i8 = 0x08;
    pub const FLAGS_PROG_8086: i8 = 0x10;
    pub const FLAGS_PROG_80286: i8 = 0x20;
    pub const FLAGS_PROG_80386: i8 = 0x40;
    pub const FLAGS_PROG_80X87: i8 = -0x80; // 0x80 as i8

    /// Is application full screen?
    pub const FLAGS_APP_FULL_SCREEN: i8 = 0x01;
    /// Is application compatible with Windows Program Manager?
    pub const FLAGS_APP_WIN_PM_COMPATIBLE: i8 = 0x02;
    /// Does application use Windows Program Manager?
    pub const FLAGS_APP_WINDOWS_PM: i8 = 0x03;
    /// Does the first segment contain code that loads the application?
    pub const FLAGS_APP_LOAD_CODE: i8 = 0x08;
    pub const FLAGS_APP_LINK_ERRS: i8 = 0x20;
    pub const FLAGS_APP_NONCONFORMING_PROG: i8 = 0x40;
    pub const FLAGS_APP_LIBRARY_MODULE: i8 = -0x80; // 0x80 as i8

    /// Unknown executable type.
    pub const EXETYPE_UNKNOWN: i8 = 0x00;
    /// OS/2 executable.
    pub const EXETYPE_OS2: i8 = 0x01;
    /// Windows executable.
    pub const EXETYPE_WINDOWS: i8 = 0x02;
    /// European DOS 4.x executable.
    pub const EXETYPE_EUROPEAN_DOS_4: i8 = 0x04;
    /// Reserved executable Type.
    pub const EXETYPE_RESERVED4: i8 = 0x08;
    /// Windows 386 executable.
    ///
    /// Note: this shares the same raw value (`0x04`) as [`Self::EXETYPE_EUROPEAN_DOS_4`] above.
    /// The original Java `switch` in `getTargetOpSysAsString` cannot have two `case` labels with
    /// the same value, so its `EXETYPE_EUROPEAN_DOS_4` case is commented out there, meaning
    /// `0x04` always resolves to "Windows 386" and `EXETYPE_EUROPEAN_DOS_4` is effectively dead.
    /// Preserved here faithfully; see [`Self::get_target_op_sys_as_string`].
    pub const EXETYPE_WINDOWS_386: i8 = 0x04;
    /// Borland Operating System Services executable.
    pub const EXETYPE_BOSS: i8 = 0x05;
    /// Pharlap 286 OS/2 executable.
    pub const EXETYPE_PHARLAP_286_OS2: i8 = -0x7f; // 0x81 as i8
    /// Pharlap 386 Windows executable.
    pub const EXETYPE_PHARLAP_286_WIN: i8 = -0x7e; // 0x82 as i8

    /// Supports long names.
    pub const OTHER_FLAGS_SUPPORTS_LONG_NAMES: i8 = 0x00;
    /// Protected mode.
    pub const OTHER_FLAGS_PROTECTED_MODE: i8 = 0x01;
    /// Proportional font.
    pub const OTHER_FLAGS_PROPORTIONAL_FONT: i8 = 0x02;
    /// Gangload area.
    pub const OTHER_FLAGS_GANGLOAD_AREA: i8 = 0x04;

    /// Constructs a new information block.
    ///
    /// # Errors
    /// Returns `Err` wrapping [`InvalidWindowsHeaderException`] (as `io::ErrorKind::InvalidData`)
    /// if the bytes at `index` do not begin with the NE magic number, or a plain IO error if
    /// there is an IO-related error reading from the reader.
    ///
    /// Note: mirroring the Java constructor exactly, the reader's pointer index is only restored
    /// to its pre-call value on a *successful* parse. If the magic number check fails, the
    /// reader is left positioned just past the two magic-number bytes it already consumed.
    pub fn new(reader: &mut dyn BinaryReader, index: u64) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let ne_magic = reader.read_next_short()?;

        if ne_magic != WindowsHeader::IMAGE_NE_SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                InvalidWindowsHeaderException::new("Not a valid Windows NE header"),
            ));
        }

        let ne_ver = reader.read_next_byte()? as i8;
        let ne_rev = reader.read_next_byte()? as i8;
        let ne_enttab = reader.read_next_short()?;
        let ne_cbenttab = reader.read_next_short()?;
        let ne_crc = reader.read_next_int()?;
        let ne_flags_prog = reader.read_next_byte()? as i8;
        let ne_flags_app = reader.read_next_byte()? as i8;
        let ne_autodata = reader.read_next_short()?;
        let ne_heap = reader.read_next_short()?;
        let ne_stack = reader.read_next_short()?;
        let ne_csip = reader.read_next_int()?;
        let ne_sssp = reader.read_next_int()?;
        let ne_cseg = reader.read_next_short()?;
        let ne_cmod = reader.read_next_short()?;
        let ne_cbnrestab = reader.read_next_short()?;
        let ne_segtab = reader.read_next_short()?;
        let ne_rsrctab = reader.read_next_short()?;
        let ne_restab = reader.read_next_short()?;
        let ne_modtab = reader.read_next_short()?;
        let ne_imptab = reader.read_next_short()?;
        let ne_nrestab = reader.read_next_int()?;
        let ne_cmovent = reader.read_next_short()?;
        let ne_align = reader.read_next_short()?;
        let ne_cres = reader.read_next_short()?;
        let ne_exetyp = reader.read_next_byte()? as i8;
        let ne_flagsothers = reader.read_next_byte()? as i8;
        let ne_pretthunks = reader.read_next_short()?;
        let ne_psegrefbytes = reader.read_next_short()?;
        let ne_swaparea = reader.read_next_short()?;
        let ne_expver = reader.read_next_short()?;

        reader.set_pointer_index(old_index);

        Ok(InformationBlock {
            ne_magic,
            ne_ver,
            ne_rev,
            ne_enttab,
            ne_cbenttab,
            ne_crc,
            ne_flags_prog,
            ne_flags_app,
            ne_autodata,
            ne_heap,
            ne_stack,
            ne_csip,
            ne_sssp,
            ne_cseg,
            ne_cmod,
            ne_cbnrestab,
            ne_segtab,
            ne_rsrctab,
            ne_restab,
            ne_modtab,
            ne_imptab,
            ne_nrestab,
            ne_cmovent,
            ne_align,
            ne_cres,
            ne_exetyp,
            ne_flagsothers,
            ne_pretthunks,
            ne_psegrefbytes,
            ne_swaparea,
            ne_expver,
        })
    }

    /// Returns the magic number.
    pub fn get_magic_number(&self) -> i16 {
        self.ne_magic
    }

    /// Returns the version number.
    pub fn get_version(&self) -> i16 {
        self.ne_ver as i16
    }

    /// Returns the revision number.
    pub fn get_revision(&self) -> i16 {
        self.ne_rev as i16
    }

    /// Returns the checksum.
    pub fn get_checksum(&self) -> i32 {
        self.ne_crc
    }

    /// Returns the initial heap size.
    pub fn get_initial_heap_size(&self) -> i16 {
        self.ne_heap
    }

    /// Returns the initial stack size.
    pub fn get_initial_stack_size(&self) -> i16 {
        self.ne_stack
    }

    /// Returns the target operating system.
    pub fn get_target_op_sys(&self) -> i8 {
        self.ne_exetyp
    }

    /// Returns the minimum code swap size.
    pub fn get_min_code_swap_size(&self) -> i16 {
        self.ne_swaparea
    }

    /// Returns the expected windows version.
    pub fn get_expected_windows_version(&self) -> i16 {
        self.ne_expver
    }

    /// Returns the automatic data segment.
    pub fn get_automatic_data_segment(&self) -> i16 {
        self.ne_autodata
    }

    /// Returns the other flags.
    pub fn get_other_flags(&self) -> i8 {
        self.ne_flagsothers
    }

    /// Returns a string representation of the other flags.
    pub fn get_other_flags_as_string(&self) -> String {
        let mut buffer = String::new();
        if (self.ne_flagsothers & Self::OTHER_FLAGS_GANGLOAD_AREA) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Gangload Area\n");
        }
        if (self.ne_flagsothers & Self::OTHER_FLAGS_PROPORTIONAL_FONT) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Proportional Font\n");
        }
        if (self.ne_flagsothers & Self::OTHER_FLAGS_PROTECTED_MODE) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Protected Mode\n");
        }
        if (self.ne_flagsothers & Self::OTHER_FLAGS_SUPPORTS_LONG_NAMES) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Long Name Support\n");
        }
        buffer
    }

    /// Returns the program flags.
    pub fn get_program_flags(&self) -> i8 {
        self.ne_flags_prog
    }

    /// Returns the application flags.
    pub fn get_application_flags(&self) -> i8 {
        self.ne_flags_app
    }

    /// Returns the segment portion of the entry point.
    pub fn get_entry_point_segment(&self) -> i16 {
        ((self.ne_csip >> 16) & 0xffff) as i16
    }

    /// Returns the offset portion of the entry point.
    pub fn get_entry_point_offset(&self) -> i16 {
        (self.ne_csip & 0xffff) as i16
    }

    /// Returns the segment portion of the stack pointer.
    pub fn get_stack_pointer_segment(&self) -> i16 {
        ((self.ne_sssp >> 16) & 0xffff) as i16
    }

    /// Returns the offset portion of the stack pointer.
    pub fn get_stack_pointer_offset(&self) -> i16 {
        (self.ne_sssp & 0xffff) as i16
    }

    /// Returns the index to the start of the segment table, relative to the beginning of the NE
    /// windows header.
    pub fn get_segment_table_offset(&self) -> i16 {
        self.ne_segtab
    }

    /// Returns the number of segments in the segment table.
    pub fn get_segment_count(&self) -> i16 {
        self.ne_cseg
    }

    /// Returns a shift count that is used to align the logical sector.
    ///
    /// This count is log2 of the segment sector size. This value corresponds to the Alignment
    /// [/a] linker switch. It is typically 4, but the default is 9. When the linker command line
    /// contains a/: 16, the shift count is 4. When the linker command line contains a/:256, the
    /// shift count is 9.
    pub fn get_segment_alignment_shift_count(&self) -> i16 {
        self.ne_align
    }

    /// Returns the index to the start of the resource table, relative to the beginning of the NE
    /// windows header.
    pub fn get_resource_table_offset(&self) -> i16 {
        self.ne_rsrctab
    }

    /// Returns the index to the start of the resident name table, relative to the beginning of
    /// the NE windows header.
    pub fn get_resident_name_table_offset(&self) -> i16 {
        self.ne_restab
    }

    /// Returns the index to the start of the modules reference table, relative to the beginning
    /// of the NE windows header.
    pub fn get_module_reference_table_offset(&self) -> i16 {
        self.ne_modtab
    }

    /// Returns the number of entries in the module reference table.
    pub fn get_module_reference_table_count(&self) -> i16 {
        self.ne_cmod
    }

    /// Returns the index to the start of the imported names table, relative to the beginning of
    /// the NE windows header.
    pub fn get_imported_names_table_offset(&self) -> i16 {
        self.ne_imptab
    }

    /// Returns the index to the start of the entry table, relative to the beginning of the NE
    /// windows header.
    pub fn get_entry_table_offset(&self) -> i16 {
        self.ne_enttab
    }

    /// Returns the number of bytes in the entry table.
    pub fn get_entry_table_size(&self) -> i16 {
        self.ne_cbenttab
    }

    /// Returns the index to the start of the segment table, relative to the beginning of the
    /// file.
    pub fn get_non_resident_name_table_offset(&self) -> i32 {
        self.ne_nrestab
    }

    /// Returns the number of bytes in the non-resident name table.
    pub fn get_non_resident_name_table_size(&self) -> i16 {
        self.ne_cbnrestab
    }

    pub fn get_moveable_entries_count(&self) -> i16 {
        self.ne_cmovent
    }

    pub fn get_resource_segment_count(&self) -> i16 {
        self.ne_cres
    }

    pub fn get_return_offset_thunk(&self) -> i16 {
        self.ne_pretthunks
    }

    pub fn get_segment_ref_byte_offset(&self) -> i16 {
        self.ne_psegrefbytes
    }

    ////////////////////////////////////////////////////////////////////

    /// Returns a string representation of the target operating system, or `None` if the value
    /// does not match any known target (mirroring the Java method's `return null;` fallback).
    pub fn get_target_op_sys_as_string(&self) -> Option<&'static str> {
        match self.ne_exetyp {
            Self::EXETYPE_UNKNOWN => Some("Unknown"),
            Self::EXETYPE_OS2 => Some("OS/2"),
            Self::EXETYPE_WINDOWS => Some("Windows"),
            // EXETYPE_EUROPEAN_DOS_4 (0x04) shares its value with EXETYPE_WINDOWS_386 below, so
            // (as in the Java `switch`, which cannot have two `case` labels with the same
            // constant) it is never matched separately here; see the doc comment on
            // `EXETYPE_WINDOWS_386`.
            Self::EXETYPE_RESERVED4 => Some("Reserved 4"),
            Self::EXETYPE_WINDOWS_386 => Some("Windows 386"),
            Self::EXETYPE_BOSS => Some("Borland Operating System Services"),
            Self::EXETYPE_PHARLAP_286_OS2 => Some("Pharlap 286 OS/2"),
            Self::EXETYPE_PHARLAP_286_WIN => Some("Pharlap 286 Windows"),
            _ => None,
        }
    }

    /// Returns a string representation of the application flags.
    pub fn get_application_flags_as_string(&self) -> String {
        let mut buffer = String::new();
        let application_type = self.ne_flags_app & 0x03;
        if application_type == Self::FLAGS_APP_FULL_SCREEN {
            buffer.push_str(TAB);
            buffer.push_str("Full Screen\n");
        } else if application_type == Self::FLAGS_APP_WIN_PM_COMPATIBLE {
            buffer.push_str(TAB);
            buffer.push_str("Windows P.M. API Compatible\n");
        } else if application_type == Self::FLAGS_APP_WINDOWS_PM {
            buffer.push_str(TAB);
            buffer.push_str("Windows P.M. API\n");
        }

        if (self.ne_flags_app & Self::FLAGS_APP_LIBRARY_MODULE) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Library Module\n");
        }
        if (self.ne_flags_app & Self::FLAGS_APP_LINK_ERRS) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Link Errors\n");
        }
        if (self.ne_flags_app & Self::FLAGS_APP_LOAD_CODE) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Load Code\n");
        }
        if (self.ne_flags_app & Self::FLAGS_APP_NONCONFORMING_PROG) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Nonconforming\n");
        }
        buffer
    }

    /// Returns a string representation of the program flags.
    pub fn get_program_flags_as_string(&self) -> String {
        let mut buffer = String::new();
        if (self.ne_flags_prog & Self::FLAGS_PROG_80286) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("80286\n");
        }
        if (self.ne_flags_prog & Self::FLAGS_PROG_80386) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("80386\n");
        }
        if (self.ne_flags_prog & Self::FLAGS_PROG_8086) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("8086\n");
        }
        if (self.ne_flags_prog & Self::FLAGS_PROG_GLOBAL_INIT) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Global Init\n");
        }
        if (self.ne_flags_prog & Self::FLAGS_PROG_SINGLE_DATA) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Single Data\n");
        }
        if (self.ne_flags_prog & Self::FLAGS_PROG_MULTIPLE_DATA) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Multi Data\n");
        }
        if (self.ne_flags_prog & Self::FLAGS_PROG_NO_AUTO_DATA) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("No Auto Data\n");
        }
        if (self.ne_flags_prog & Self::FLAGS_PROG_PROTECTED_MODE) != 0 {
            buffer.push_str(TAB);
            buffer.push_str("Protected Mode\n");
        }
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::GByteStore;

    struct VecProvider(Vec<u8>);

    impl GByteStore for VecProvider {
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
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn GByteStore>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
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
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
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

    /// Builds a full, valid 64-byte NE `InformationBlock`, with every field distinguishable so
    /// tests can catch field-ordering mistakes.
    fn build_information_block() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&WindowsHeader::IMAGE_NE_SIGNATURE.to_le_bytes()); // ne_magic
        data.push(5); // ne_ver
        data.push(6); // ne_rev
        data.extend_from_slice(&0x0100i16.to_le_bytes()); // ne_enttab
        data.extend_from_slice(&0x0010i16.to_le_bytes()); // ne_cbenttab
        data.extend_from_slice(&0x12345678i32.to_le_bytes()); // ne_crc
        data.push(InformationBlock::FLAGS_PROG_80386 as u8); // ne_flags_prog
        data.push(InformationBlock::FLAGS_APP_LOAD_CODE as u8); // ne_flags_app
        data.extend_from_slice(&7i16.to_le_bytes()); // ne_autodata
        data.extend_from_slice(&0x2000i16.to_le_bytes()); // ne_heap
        data.extend_from_slice(&0x3000i16.to_le_bytes()); // ne_stack
        data.extend_from_slice(&0x00050010i32.to_le_bytes()); // ne_csip (segment 5, offset 0x10)
        data.extend_from_slice(&0x00060020i32.to_le_bytes()); // ne_sssp (segment 6, offset 0x20)
        data.extend_from_slice(&3i16.to_le_bytes()); // ne_cseg
        data.extend_from_slice(&2i16.to_le_bytes()); // ne_cmod
        data.extend_from_slice(&0x0040i16.to_le_bytes()); // ne_cbnrestab
        data.extend_from_slice(&0x0200i16.to_le_bytes()); // ne_segtab
        data.extend_from_slice(&0x0300i16.to_le_bytes()); // ne_rsrctab
        data.extend_from_slice(&0x0400i16.to_le_bytes()); // ne_restab
        data.extend_from_slice(&0x0500i16.to_le_bytes()); // ne_modtab
        data.extend_from_slice(&0x0600i16.to_le_bytes()); // ne_imptab
        data.extend_from_slice(&0x00070000i32.to_le_bytes()); // ne_nrestab
        data.extend_from_slice(&9i16.to_le_bytes()); // ne_cmovent
        data.extend_from_slice(&4i16.to_le_bytes()); // ne_align
        data.extend_from_slice(&2i16.to_le_bytes()); // ne_cres
        data.push(InformationBlock::EXETYPE_WINDOWS as u8); // ne_exetyp
        data.push(InformationBlock::OTHER_FLAGS_PROTECTED_MODE as u8); // ne_flagsothers
        data.extend_from_slice(&0x0800i16.to_le_bytes()); // ne_pretthunks
        data.extend_from_slice(&0x0900i16.to_le_bytes()); // ne_psegrefbytes
        data.extend_from_slice(&0x0A00i16.to_le_bytes()); // ne_swaparea
        data.extend_from_slice(&0x0300i16.to_le_bytes()); // ne_expver
        assert_eq!(data.len(), 64);
        data
    }

    #[test]
    fn parses_all_fields_in_order() {
        let mut reader = MockReader::new(build_information_block());

        let ib = InformationBlock::new(&mut reader, 0).unwrap();

        assert_eq!(ib.get_magic_number(), WindowsHeader::IMAGE_NE_SIGNATURE);
        assert_eq!(ib.get_version(), 5);
        assert_eq!(ib.get_revision(), 6);
        assert_eq!(ib.get_entry_table_offset(), 0x0100);
        assert_eq!(ib.get_entry_table_size(), 0x0010);
        assert_eq!(ib.get_checksum(), 0x12345678);
        assert_eq!(ib.get_program_flags(), InformationBlock::FLAGS_PROG_80386);
        assert_eq!(
            ib.get_application_flags(),
            InformationBlock::FLAGS_APP_LOAD_CODE
        );
        assert_eq!(ib.get_automatic_data_segment(), 7);
        assert_eq!(ib.get_initial_heap_size(), 0x2000);
        assert_eq!(ib.get_initial_stack_size(), 0x3000);
        assert_eq!(ib.get_entry_point_segment(), 5);
        assert_eq!(ib.get_entry_point_offset(), 0x0010);
        assert_eq!(ib.get_stack_pointer_segment(), 6);
        assert_eq!(ib.get_stack_pointer_offset(), 0x0020);
        assert_eq!(ib.get_segment_count(), 3);
        assert_eq!(ib.get_module_reference_table_count(), 2);
        assert_eq!(ib.get_non_resident_name_table_size(), 0x0040);
        assert_eq!(ib.get_segment_table_offset(), 0x0200);
        assert_eq!(ib.get_resource_table_offset(), 0x0300);
        assert_eq!(ib.get_resident_name_table_offset(), 0x0400);
        assert_eq!(ib.get_module_reference_table_offset(), 0x0500);
        assert_eq!(ib.get_imported_names_table_offset(), 0x0600);
        assert_eq!(ib.get_non_resident_name_table_offset(), 0x00070000);
        assert_eq!(ib.get_moveable_entries_count(), 9);
        assert_eq!(ib.get_segment_alignment_shift_count(), 4);
        assert_eq!(ib.get_resource_segment_count(), 2);
        assert_eq!(
            ib.get_target_op_sys(),
            InformationBlock::EXETYPE_WINDOWS
        );
        assert_eq!(
            ib.get_other_flags(),
            InformationBlock::OTHER_FLAGS_PROTECTED_MODE
        );
        assert_eq!(ib.get_return_offset_thunk(), 0x0800);
        assert_eq!(ib.get_segment_ref_byte_offset(), 0x0900);
        assert_eq!(ib.get_min_code_swap_size(), 0x0A00);
        assert_eq!(ib.get_expected_windows_version(), 0x0300);
    }

    #[test]
    fn rejects_bad_magic_number() {
        let mut data = build_information_block();
        data[0..2].copy_from_slice(&0x1234i16.to_le_bytes());
        let mut reader = MockReader::new(data);

        let err = InformationBlock::new(&mut reader, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bad_magic_leaves_reader_advanced_past_the_magic_bytes() {
        // Mirrors the Java constructor exactly: on a bad-magic failure, the reader position is
        // *not* restored (unlike a successful parse, which does restore it). This is a real
        // quirk: `setPointerIndex(oldIndex)` only appears once, at the very end of the Java
        // constructor, after the exception-throwing check.
        let mut data = build_information_block();
        data[0..2].copy_from_slice(&0x1234i16.to_le_bytes());
        let mut reader = MockReader::new(data);
        reader.set_pointer_index(5);

        let _ = InformationBlock::new(&mut reader, 0).unwrap_err();

        // index=0 was set, then 2 bytes were consumed reading the (bad) magic number.
        assert_eq!(reader.get_pointer_index(), 2);
    }

    #[test]
    fn restores_reader_position_after_successful_parse() {
        let mut reader = MockReader::new(build_information_block());
        reader.set_pointer_index(7);

        let _ = InformationBlock::new(&mut reader, 0).unwrap();

        assert_eq!(reader.get_pointer_index(), 7);
    }

    #[test]
    fn honors_starting_index() {
        let mut data = vec![0xAAu8; 10];
        data.extend_from_slice(&build_information_block());
        let mut reader = MockReader::new(data);

        let ib = InformationBlock::new(&mut reader, 10).unwrap();

        assert_eq!(ib.get_magic_number(), WindowsHeader::IMAGE_NE_SIGNATURE);
    }

    #[test]
    fn errors_on_truncated_data() {
        let data = vec![0x4E, 0x45]; // just the magic number, nothing else
        let mut reader = MockReader::new(data);

        assert!(InformationBlock::new(&mut reader, 0).is_err());
    }

    #[test]
    fn other_flags_as_string_lists_set_bits() {
        let mut data = build_information_block();
        data[55] = (InformationBlock::OTHER_FLAGS_GANGLOAD_AREA
            | InformationBlock::OTHER_FLAGS_PROPORTIONAL_FONT) as u8;
        let mut reader = MockReader::new(data);

        let ib = InformationBlock::new(&mut reader, 0).unwrap();
        let s = ib.get_other_flags_as_string();

        assert!(s.contains("Gangload Area"));
        assert!(s.contains("Proportional Font"));
        assert!(!s.contains("Protected Mode"));
    }

    #[test]
    fn other_flags_as_string_empty_when_value_is_zero_flag_only() {
        // OTHER_FLAGS_SUPPORTS_LONG_NAMES == 0x00, so `(flags & 0x00) != 0` is always false: the
        // Java code can never actually append "Long Name Support" via that check. This is a
        // genuine quirk in the original (the mask being tested is 0, so the bitwise AND is
        // always 0), preserved here as-is.
        let mut data = build_information_block();
        data[55] = 0; // ne_flagsothers = 0
        let mut reader = MockReader::new(data);

        let ib = InformationBlock::new(&mut reader, 0).unwrap();
        let s = ib.get_other_flags_as_string();

        assert!(s.is_empty());
        assert!(!s.contains("Long Name Support"));
    }

    #[test]
    fn application_flags_as_string_reports_application_type_and_bit_flags() {
        let mut data = build_information_block();
        data[13] = (InformationBlock::FLAGS_APP_WINDOWS_PM
            | InformationBlock::FLAGS_APP_LINK_ERRS) as u8;
        let mut reader = MockReader::new(data);

        let ib = InformationBlock::new(&mut reader, 0).unwrap();
        let s = ib.get_application_flags_as_string();

        assert!(s.contains("Windows P.M. API\n"));
        assert!(s.contains("Link Errors"));
        assert!(!s.contains("Full Screen"));
    }

    #[test]
    fn program_flags_as_string_reports_set_bits() {
        let mut data = build_information_block();
        data[12] = (InformationBlock::FLAGS_PROG_80286
            | InformationBlock::FLAGS_PROG_PROTECTED_MODE) as u8;
        let mut reader = MockReader::new(data);

        let ib = InformationBlock::new(&mut reader, 0).unwrap();
        let s = ib.get_program_flags_as_string();

        assert!(s.contains("80286"));
        assert!(s.contains("Protected Mode"));
        assert!(!s.contains("80386"));
    }

    #[test]
    fn target_op_sys_as_string_maps_known_values() {
        let mut data = build_information_block();

        data[54] = InformationBlock::EXETYPE_UNKNOWN as u8;
        let mut reader = MockReader::new(data.clone());
        assert_eq!(
            InformationBlock::new(&mut reader, 0)
                .unwrap()
                .get_target_op_sys_as_string(),
            Some("Unknown")
        );

        data[54] = InformationBlock::EXETYPE_WINDOWS_386 as u8;
        let mut reader = MockReader::new(data.clone());
        assert_eq!(
            InformationBlock::new(&mut reader, 0)
                .unwrap()
                .get_target_op_sys_as_string(),
            Some("Windows 386")
        );

        data[54] = InformationBlock::EXETYPE_PHARLAP_286_WIN as u8;
        let mut reader = MockReader::new(data.clone());
        assert_eq!(
            InformationBlock::new(&mut reader, 0)
                .unwrap()
                .get_target_op_sys_as_string(),
            Some("Pharlap 286 Windows")
        );
    }

    #[test]
    fn target_op_sys_as_string_is_none_for_unmapped_value() {
        let mut data = build_information_block();
        data[54] = 0x7f; // not any defined EXETYPE_* constant
        let mut reader = MockReader::new(data);

        let ib = InformationBlock::new(&mut reader, 0).unwrap();
        assert_eq!(ib.get_target_op_sys_as_string(), None);
    }

    #[test]
    fn european_dos_4_resolves_to_windows_386_due_to_shared_constant_value() {
        // EXETYPE_EUROPEAN_DOS_4 == EXETYPE_WINDOWS_386 == 0x04: the Java `switch` can only
        // dispatch on the raw value, and its `EXETYPE_EUROPEAN_DOS_4` case is commented out
        // (duplicate `case` label), so this value always reports "Windows 386".
        let mut data = build_information_block();
        data[54] = InformationBlock::EXETYPE_EUROPEAN_DOS_4 as u8;
        let mut reader = MockReader::new(data);

        let ib = InformationBlock::new(&mut reader, 0).unwrap();
        assert_eq!(ib.get_target_op_sys_as_string(), Some("Windows 386"));
    }
}
