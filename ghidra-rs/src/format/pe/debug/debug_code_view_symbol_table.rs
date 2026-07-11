use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_code_view_constants as cv;
use super::o_m_f_dir_entry::OmfDirEntry;
use super::o_m_f_dir_header::OmfDirHeader;
use super::o_m_f_file_index::OmfFileIndex;
use super::o_m_f_global::OmfGlobal;
use super::o_m_f_module::OmfModule;
use super::o_m_f_seg_map::OmfSegMap;
use super::o_m_f_src_module::OmfSrcModule;
use super::omf_align_sym::OmfAlignSym;
use super::omf_library::OmfLibrary;

/// Represents the Object Module Format (OMF) code view symbol table.
///
/// Mirrors the `DebugCodeViewSymbolTable` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// The Java class also implements `StructConverter`, but its `toDataType()`
/// always returns `null` there, so no meaningful `DataType` can be produced;
/// that method is intentionally not ported.
pub struct DebugCodeViewSymbolTable {
    magic: Vec<u8>,
    entries_list: Vec<OmfDirEntry>,
    modules_list: Vec<OmfModule>,
    globals_list: Vec<OmfGlobal>,
    seg_maps_list: Vec<OmfSegMap>,
    src_module_list: Vec<OmfSrcModule>,
    file_index_list: Vec<OmfFileIndex>,
    align_syms_list: Vec<OmfAlignSym>,
    library: Option<OmfLibrary>,
}

impl DebugCodeViewSymbolTable {
    /// Magic value for the CodeView NB09 format.
    pub const MAGIC_NB_09: i32 = ((cv::SIGNATURE_NB as i32) << 16) | (cv::VERSION_09 as i32);
    /// Magic value for the CodeView NB11 format.
    pub const MAGIC_NB_11: i32 = ((cv::SIGNATURE_NB as i32) << 16) | (cv::VERSION_11 as i32);
    /// Magic value for the CodeView N1 1.2 format.
    pub const MAGIC_N1_12: i32 = ((cv::SIGNATURE_N1 as i32) << 16) | (cv::VERSION_12 as i32);
    /// Magic value for the CodeView N1 1.3 format.
    pub const MAGIC_N1_13: i32 = ((cv::SIGNATURE_N1 as i32) << 16) | (cv::VERSION_13 as i32);

    /// Returns true if the four bytes at `ptr` match a known CodeView magic value.
    ///
    /// Mirrors `DebugCodeViewSymbolTable.isMatch(BinaryReader, int)`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn is_match(reader: &dyn BinaryReader, ptr: u64) -> io::Result<bool> {
        // Read the value out as big endian, mirroring the Java implementation's
        // byte-by-byte reconstruction (including its signed-byte promotion).
        let b0 = reader.read_byte(ptr)? as i8 as i32;
        let b1 = reader.read_byte(ptr + 1)? as i8 as i32;
        let b2 = reader.read_byte(ptr + 2)? as i8 as i32;
        let b3 = reader.read_byte(ptr + 3)? as i8 as i32;
        let value = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

        Ok(value == Self::MAGIC_NB_09
            || value == Self::MAGIC_NB_11
            || value == Self::MAGIC_N1_12
            || value == Self::MAGIC_N1_13)
    }

    /// Creates a new `DebugCodeViewSymbolTable` by reading from the given binary
    /// reader, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `_size` - Mirrors the Java constructor's `size` parameter, which is
    ///   likewise unused in the original constructor body.
    /// * `base` - The base offset that OMF directory entry offsets are relative to.
    /// * `ptr` - The starting byte offset of the symbol table magic bytes.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, _size: i32, base: i32, ptr: i32) -> io::Result<Self> {
        let magic = reader.read_byte_array(ptr as u32 as u64, 4)?;
        let ptr = ptr.wrapping_add(4);

        let lfo_directory_pos = reader.read_int(ptr as u32 as u64)?;
        let omf_dir_header_pos = base.wrapping_add(lfo_directory_pos);
        let header = OmfDirHeader::new(reader, omf_dir_header_pos as u32 as u64)?;
        let mut omf_dir_entry_pos = omf_dir_header_pos.wrapping_add(OmfDirHeader::SIZE as i32);

        let mut entries_list = Vec::new();
        let mut modules_list = Vec::new();
        let mut globals_list = Vec::new();
        let mut seg_maps_list = Vec::new();
        let mut src_module_list = Vec::new();
        let mut file_index_list = Vec::new();
        let mut align_syms_list = Vec::new();
        let mut library = None;

        for _ in 0..header.number_of_entries() {
            let entry = OmfDirEntry::new(reader, omf_dir_entry_pos as u32 as u64)?;

            let subsection_pos = entry.large_file_offset().wrapping_add(base) as u32 as u64;
            let subsection_bytes = entry.number_of_bytes();

            match entry.subsection_type() as u32 {
                cv::SST_MODULE => {
                    modules_list.push(OmfModule::new(reader, subsection_pos, subsection_bytes)?);
                }
                cv::SST_SEG_MAP => {
                    seg_maps_list.push(OmfSegMap::new(reader, subsection_pos)?);
                }
                cv::SST_GLOBAL_PUB | cv::SST_GLOBAL_SYM | cv::SST_STATIC_SYM => {
                    globals_list.push(OmfGlobal::new(reader, subsection_pos)?);
                }
                cv::SST_SRC_MODULE => {
                    src_module_list.push(OmfSrcModule::new(reader, subsection_pos)?);
                }
                cv::SST_FILE_INDEX => {
                    file_index_list.push(OmfFileIndex::new(reader, subsection_pos)?);
                }
                cv::SST_ALIGN_SYM => {
                    align_syms_list.push(OmfAlignSym::new(reader, subsection_pos)?);
                }
                cv::SST_LIBRARIES => {
                    library = Some(OmfLibrary::new(
                        reader,
                        subsection_pos,
                        subsection_bytes as u32 as u64,
                    )?);
                }
                cv::SST_GLOBAL_TYPES => {
                    // Mirrors the Java case, which intentionally does nothing further.
                }
                _ => {
                    // Mirrors the Java default case, which intentionally does nothing further.
                }
            }

            entries_list.push(entry);
            omf_dir_entry_pos = omf_dir_entry_pos.wrapping_add(OmfDirEntry::SIZE as i32);
        }

        Ok(DebugCodeViewSymbolTable {
            magic,
            entries_list,
            modules_list,
            globals_list,
            seg_maps_list,
            src_module_list,
            file_index_list,
            align_syms_list,
            library,
        })
    }

    /// Returns the magic bytes.
    pub fn magic(&self) -> &[u8] {
        &self.magic
    }

    /// Returns the OMF library, if present.
    pub fn omf_library(&self) -> Option<&OmfLibrary> {
        self.library.as_ref()
    }

    /// Returns the OMF directory entries.
    pub fn omf_directory_entries(&self) -> &[OmfDirEntry] {
        &self.entries_list
    }

    /// Returns the OMF modules.
    pub fn omf_modules(&self) -> &[OmfModule] {
        &self.modules_list
    }

    /// Returns the OMF segment maps.
    pub fn omf_seg_maps(&self) -> &[OmfSegMap] {
        &self.seg_maps_list
    }

    /// Returns the OMF globals.
    pub fn omf_globals(&self) -> &[OmfGlobal] {
        &self.globals_list
    }

    /// Returns the OMF source modules.
    pub fn omf_src_modules(&self) -> &[OmfSrcModule] {
        &self.src_module_list
    }

    /// Returns the OMF source files.
    pub fn omf_files(&self) -> &[OmfFileIndex] {
        &self.file_index_list
    }

    /// Returns the OMF align symbols.
    pub fn omf_align_sym(&self) -> &[OmfAlignSym] {
        &self.align_syms_list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

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
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
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

    #[test]
    fn magic_constants() {
        assert_eq!(DebugCodeViewSymbolTable::MAGIC_NB_09, 0x4e423039);
        assert_eq!(DebugCodeViewSymbolTable::MAGIC_NB_11, 0x4e423131);
        assert_eq!(DebugCodeViewSymbolTable::MAGIC_N1_12, 0x4e313140);
        assert_eq!(DebugCodeViewSymbolTable::MAGIC_N1_13, 0x4e3130f0);
    }

    #[test]
    fn is_match_recognizes_nb09() {
        let data = vec![0x4e, 0x42, 0x30, 0x39];
        let reader = MockReader::new(data, true);

        assert!(DebugCodeViewSymbolTable::is_match(&reader, 0).expect("failed to read"));
    }

    #[test]
    fn is_match_rejects_unknown_signature() {
        let data = vec![0x00, 0x00, 0x00, 0x00];
        let reader = MockReader::new(data, true);

        assert!(!DebugCodeViewSymbolTable::is_match(&reader, 0).expect("failed to read"));
    }

    /// Builds a symbol table image with an `OMFModule` entry and an `OMFLibrary`
    /// entry, and verifies the constructor parses both.
    #[test]
    fn read_symbol_table_with_module_and_library() {
        let mut data = vec![
            0x4e, 0x42, 0x30, 0x39, // magic = "NB09"
            0x08, 0x00, 0x00, 0x00, // lfoDirectoryPos = 8
        ];
        // OMFDirHeader at offset 8 (16 bytes).
        data.extend_from_slice(&[
            0x10, 0x00, // cbDirHeader = 16
            0x0C, 0x00, // cbDirEntry = 12
            0x02, 0x00, 0x00, 0x00, // cDir = 2 entries
            0x00, 0x00, 0x00, 0x00, // lfoNextDir = 0
            0x00, 0x00, 0x00, 0x00, // flags = 0
        ]);
        // Entry 1 at offset 24: sstModule, payload at offset 48, 12 bytes.
        data.extend_from_slice(&[
            0x20, 0x01, // subsection = sstModule (0x120)
            0x00, 0x00, // imod = 0
            0x30, 0x00, 0x00, 0x00, // lfo = 48
            0x0C, 0x00, 0x00, 0x00, // cb = 12
        ]);
        // Entry 2 at offset 36: sstLibraries, payload at offset 60, 4 bytes.
        data.extend_from_slice(&[
            0x28, 0x01, // subsection = sstLibraries (0x128)
            0x00, 0x00, // imod = 0
            0x3C, 0x00, 0x00, 0x00, // lfo = 60
            0x04, 0x00, 0x00, 0x00, // cb = 4
        ]);
        // OMFModule payload at offset 48 (12 bytes).
        data.extend_from_slice(&[
            0x01, 0x00, // ovlNumber = 1
            0x02, 0x00, // iLib = 2
            0x00, 0x00, // cSeg = 0
            0x43, 0x56, // style = "CV"
            0xFF, // pad byte
        ]);
        data.extend_from_slice(b"hi\x00"); // name = "hi"
        // OMFLibrary payload at offset 60 (4 bytes): one 3-byte name "abc".
        data.push(0x03);
        data.extend_from_slice(b"abc");

        let reader = MockReader::new(data, true);
        let table = DebugCodeViewSymbolTable::new(&reader, 0, 0, 0).expect("failed to read");

        assert_eq!(table.magic(), &[0x4e, 0x42, 0x30, 0x39]);
        assert_eq!(table.omf_directory_entries().len(), 2);

        assert_eq!(table.omf_modules().len(), 1);
        assert_eq!(table.omf_modules()[0].name(), "hi");
        assert_eq!(table.omf_modules()[0].ovl_number(), 1);
        assert_eq!(table.omf_modules()[0].i_lib(), 2);

        let library = table.omf_library().expect("expected a library entry");
        assert_eq!(library.libraries(), &["abc".to_string()]);

        assert!(table.omf_seg_maps().is_empty());
        assert!(table.omf_globals().is_empty());
        assert!(table.omf_src_modules().is_empty());
        assert!(table.omf_files().is_empty());
        assert!(table.omf_align_sym().is_empty());
    }

    #[test]
    fn read_symbol_table_with_no_entries() {
        let mut data = vec![
            0xAA, 0xAA, 0xAA, 0xAA, // magic (unchecked)
            0x08, 0x00, 0x00, 0x00, // lfoDirectoryPos = 8
        ];
        data.extend_from_slice(&[
            0x10, 0x00, // cbDirHeader = 16
            0x0C, 0x00, // cbDirEntry = 12
            0x00, 0x00, 0x00, 0x00, // cDir = 0 entries
            0x00, 0x00, 0x00, 0x00, // lfoNextDir = 0
            0x00, 0x00, 0x00, 0x00, // flags = 0
        ]);

        let reader = MockReader::new(data, true);
        let table = DebugCodeViewSymbolTable::new(&reader, 0, 0, 0).expect("failed to read");

        assert!(table.omf_directory_entries().is_empty());
        assert!(table.omf_modules().is_empty());
        assert!(table.omf_library().is_none());
    }
}
