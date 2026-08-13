use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::imported_name_table::ImportedNameTable;
use crate::format::ne::module_reference_table::ModuleReferenceTable;
use crate::format::ne::non_resident_name_table::NonResidentNameTable;
use crate::format::ne::resident_name_table::ResidentNameTable;
use crate::format::ne::resource_table::ResourceTable;
use crate::format::seam_stubs::{EntryTable, InformationBlock, SegmentTable};
use crate::program::model::address::segmented_address::SegmentedAddress;
use std::io;

/// Represents and parses the Windows new-style executable (NE) header.
///
/// Mirrors `WindowsHeader` from the original Ghidra Java source.
pub struct WindowsHeader {
    info_block: InformationBlock,
    seg_table: SegmentTable,
    rsrc_table: Option<ResourceTable>,
    res_name_table: ResidentNameTable,
    mod_ref_table: ModuleReferenceTable,
    imp_name_table: ImportedNameTable,
    entry_table: EntryTable,
    non_res_name_table: NonResidentNameTable,
}

impl WindowsHeader {
    /// The magic number for Windows NE files.
    pub const IMAGE_NE_SIGNATURE: i16 = 0x454E; // NE

    /// Constructs a new Windows header.
    ///
    /// # Arguments
    /// * `reader` - the binary reader
    /// * `base_addr` - the image base address, or `None` if not known
    /// * `index` - the index where the windows header begins
    ///
    /// # Errors
    /// Returns `Err` if the bytes defined in the binary reader at the specified index do not
    /// constitute a valid Windows header, or if there is an IO-related error reading the header
    /// bytes.
    pub fn new(
        reader: &mut dyn BinaryReader,
        base_addr: Option<&SegmentedAddress>,
        index: u64,
    ) -> io::Result<Self> {
        let info_block = InformationBlock::new(reader, index)?;

        let seg_table_index = offset_index(info_block.get_segment_table_offset(), index);
        let seg_table = SegmentTable::new(
            reader,
            base_addr,
            seg_table_index,
            info_block.get_segment_count(),
            info_block.get_segment_alignment_shift_count(),
        )?;

        // if resource table offset == resident name table offset, then
        // we do not have any resources...
        let rsrc_table = if info_block.get_resource_table_offset()
            != info_block.get_resident_name_table_offset()
        {
            let rsrc_table_index = offset_index(info_block.get_resource_table_offset(), index);
            Some(ResourceTable::new(reader, rsrc_table_index)?)
        } else {
            None
        };

        let res_name_table_index =
            offset_index(info_block.get_resident_name_table_offset(), index);
        let res_name_table = ResidentNameTable::new(reader, res_name_table_index)?;

        let imp_name_table_index =
            offset_index(info_block.get_imported_names_table_offset(), index);
        let imp_name_table = ImportedNameTable::new(reader.clone_reader(), imp_name_table_index);

        let mod_ref_table_index =
            offset_index(info_block.get_module_reference_table_offset(), index);
        let mod_ref_table = ModuleReferenceTable::new(
            reader.clone_reader(),
            mod_ref_table_index,
            info_block.get_module_reference_table_count(),
            &imp_name_table,
        )?;

        let entry_table_index = offset_index(info_block.get_entry_table_offset(), index);
        let entry_table = EntryTable::new(
            reader,
            entry_table_index,
            info_block.get_entry_table_size(),
        )?;

        let non_res_name_table = NonResidentNameTable::new(
            reader,
            info_block.get_non_resident_name_table_offset() as u64,
            info_block.get_non_resident_name_table_size(),
        )?;

        Ok(WindowsHeader {
            info_block,
            seg_table,
            rsrc_table,
            res_name_table,
            mod_ref_table,
            imp_name_table,
            entry_table,
            non_res_name_table,
        })
    }

    /// Returns the processor name.
    // TODO: how to properly determine the processor name? is there more than one?
    pub fn get_processor_name(&self) -> &'static str {
        "x86"
    }

    /// Returns the information block.
    pub fn get_information_block(&self) -> &InformationBlock {
        &self.info_block
    }

    /// Returns the segment table.
    pub fn get_segment_table(&self) -> &SegmentTable {
        &self.seg_table
    }

    /// Returns the resource table, or `None` if this header has no resources.
    pub fn get_resource_table(&self) -> Option<&ResourceTable> {
        self.rsrc_table.as_ref()
    }

    /// Returns the resident name table.
    pub fn get_resident_name_table(&self) -> &ResidentNameTable {
        &self.res_name_table
    }

    /// Returns the module reference table.
    pub fn get_module_reference_table(&self) -> &ModuleReferenceTable {
        &self.mod_ref_table
    }

    /// Returns the imported name table.
    pub fn get_imported_name_table(&self) -> &ImportedNameTable {
        &self.imp_name_table
    }

    /// Returns the entry table.
    pub fn get_entry_table(&self) -> &EntryTable {
        &self.entry_table
    }

    /// Returns the non-resident name table.
    pub fn get_non_resident_name_table(&self) -> &NonResidentNameTable {
        &self.non_res_name_table
    }
}

/// Adds a table offset (relative to the beginning of the NE header) to `index`, mirroring the
/// Java `infoBlock.getXxxOffset() + index` int arithmetic (the short offset is sign-extended,
/// then the sum is reinterpreted as an unsigned file position).
fn offset_index(table_offset: i16, index: u64) -> u64 {
    (table_offset as i64 + index as i64) as u64
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
        provider: Rc<RefCell<dyn ByteProvider>>,
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

    /// Builds a minimal, but structurally valid, 75-byte NE image:
    /// - bytes 0..64: the `InformationBlock` (64-byte NE header)
    /// - bytes 64..72: a single all-zero `Segment` (no data, no relocations)
    /// - byte 72: an empty resident name table (also used as the resource table offset, so no
    ///   resource table is created)
    /// - byte 73: an empty entry table (also used, unread, for the module reference/imported
    ///   name table offsets since their counts are zero)
    /// - byte 74: an empty non-resident name table
    fn minimal_ne_image() -> Vec<u8> {
        let mut data = vec![0u8; 75];

        data[0..2].copy_from_slice(&WindowsHeader::IMAGE_NE_SIGNATURE.to_le_bytes()); // ne_magic
        // ne_ver, ne_rev: 2 bytes, left zero
        data[4..6].copy_from_slice(&73i16.to_le_bytes()); // ne_enttab
        // ne_cbenttab, ne_crc, ne_flags_prog, ne_flags_app, ne_autodata, ne_heap, ne_stack,
        // ne_csip, ne_sssp: left zero
        data[28..30].copy_from_slice(&1i16.to_le_bytes()); // ne_cseg
        // ne_cmod = 0, ne_cbnrestab = 0: left zero
        data[34..36].copy_from_slice(&64i16.to_le_bytes()); // ne_segtab
        data[36..38].copy_from_slice(&72i16.to_le_bytes()); // ne_rsrctab
        data[38..40].copy_from_slice(&72i16.to_le_bytes()); // ne_restab
        data[40..42].copy_from_slice(&73i16.to_le_bytes()); // ne_modtab
        data[42..44].copy_from_slice(&73i16.to_le_bytes()); // ne_imptab
        data[44..48].copy_from_slice(&74i32.to_le_bytes()); // ne_nrestab (absolute offset)
        // ne_cmovent, ne_align (shift count 0), ne_cres, ne_exetyp, ne_flagsothers,
        // ne_pretthunks, ne_psegrefbytes, ne_swaparea, ne_expver: left zero

        data
    }

    #[test]
    fn parses_minimal_header() {
        let mut reader = MockReader::new(minimal_ne_image());

        let header = WindowsHeader::new(&mut reader, None, 0).unwrap();

        assert_eq!(header.get_processor_name(), "x86");
        assert!(header.get_resource_table().is_none());
        assert_eq!(header.get_segment_table().get_segments().len(), 1);
        assert_eq!(header.get_resident_name_table().names().len(), 0);
        assert_eq!(header.get_module_reference_table().offsets().len(), 0);
        assert_eq!(header.get_entry_table().get_bundles().len(), 0);
        assert_eq!(header.get_non_resident_name_table().title(), "<not set>");
    }

    #[test]
    fn rejects_bad_magic_number() {
        let mut data = minimal_ne_image();
        data[0..2].copy_from_slice(&0x1234i16.to_le_bytes());
        let mut reader = MockReader::new(data);

        match WindowsHeader::new(&mut reader, None, 0) {
            Ok(_) => panic!("expected an error for a bad magic number"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidData),
        }
    }

    #[test]
    fn restores_reader_position_after_construction() {
        let mut reader = MockReader::new(minimal_ne_image());
        reader.set_pointer_index(5);

        let _ = WindowsHeader::new(&mut reader, None, 0).unwrap();

        assert_eq!(reader.get_pointer_index(), 5);
    }
}
