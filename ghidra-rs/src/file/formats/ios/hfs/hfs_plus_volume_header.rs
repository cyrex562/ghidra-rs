use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// Magic value `'H+'` (`0x482b`) identifying an HFS+ volume header.
const HFSPLUS_SIGNATURE_MAGIC: i16 = 0x482b;
#[allow(dead_code)]
/// Magic value `'HX'` (`0x4858`) identifying an HFSX volume header.
const HFSX_SIGNATURE_MAGIC: i16 = 0x4858;
const HFSPLUS_VERSION: i16 = 4;
#[allow(dead_code)]
const HFSX_VERSION: i16 = 5;

/// Size, in bytes, of an HFS+ volume header block.
const SIZEOF_HEADER: u64 = 512;

/// Default byte offset of the volume header within an HFS+ volume.
const DEFAULT_OFFSET: u64 = 1024;

/// Apple HFS+ volume header.
///
/// See <https://developer.apple.com/library/archive/technotes/tn/tn1150.html#VolumeHeader>.
///
/// Fields are big-endian.
///
/// Mirrors `ghidra.file.formats.ios.hfs.HFSPlusVolumeHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsPlusVolumeHeader {
    signature: i16,
    version: i16,
    attributes: i32,
    last_mounted_version: i32,
    journal_info_block: i32,

    create_date: i32,
    modify_date: i32,
    backup_date: i32,
    checked_date: i32,

    file_count: i32,
    folder_count: i32,

    block_size: i32,
    total_blocks: i32,
    free_blocks: i32,

    next_allocation: i32,
    rsrc_clump_size: i32,
    data_clump_size: i32,
    next_catalog_id: i32,

    write_count: i32,
    encodings_bitmap: i64,

    finder_info: Vec<i32>,

    raw_fork_data: Vec<u8>,
    // HFSPlusForkData     allocationFile; // 70           80
    // HFSPlusForkData     extentsFile;    // C0           80
    // HFSPlusForkData     catalogFile;    // 110          80
    // HFSPlusForkData     attributesFile; // 160          80
    // HFSPlusForkData     startupFile;    // 1B0          80
}

impl HfsPlusVolumeHeader {
    /// Returns true if a valid, well-formed HFS+ volume header is present in `reader`.
    ///
    /// Mirrors Java's `probe`, which swallows I/O errors and reports `false` instead of
    /// propagating them.
    pub fn probe(reader: &mut dyn BinaryReader) -> bool {
        let length = match reader.length() {
            Ok(l) => l,
            Err(_) => return false,
        };
        if length < DEFAULT_OFFSET + SIZEOF_HEADER {
            return false;
        }
        let header = match Self::read(reader) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if !header.is_valid() {
            return false;
        }
        let provider = reader.get_byte_provider();
        let mut bp = provider.borrow_mut();
        header.has_good_volume_info(&mut *bp).unwrap_or(false)
    }

    /// Reads an [`HfsPlusVolumeHeader`] from the default offset (1024) of `reader`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from `reader` fails.
    pub fn read(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Self::read_at(reader, DEFAULT_OFFSET)
    }

    /// Reads an [`HfsPlusVolumeHeader`] from the specified offset of `reader`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from `reader` fails.
    pub fn read_at(reader: &mut dyn BinaryReader, offset: u64) -> io::Result<Self> {
        reader.set_little_endian(false);
        reader.set_pointer_index(offset);

        let signature = reader.read_next_short()?;
        let version = reader.read_next_short()?;
        let attributes = reader.read_next_int()?;
        let last_mounted_version = reader.read_next_int()?;
        let journal_info_block = reader.read_next_int()?;

        let create_date = reader.read_next_int()?;
        let modify_date = reader.read_next_int()?;
        let backup_date = reader.read_next_int()?;
        let checked_date = reader.read_next_int()?;

        let file_count = reader.read_next_int()?;
        let folder_count = reader.read_next_int()?;

        let block_size = reader.read_next_int()?;
        let total_blocks = reader.read_next_int()?;
        let free_blocks = reader.read_next_int()?;

        let next_allocation = reader.read_next_int()?;
        let rsrc_clump_size = reader.read_next_int()?;
        let data_clump_size = reader.read_next_int()?;
        let next_catalog_id = reader.read_next_int()?;

        let write_count = reader.read_next_int()?;
        let encodings_bitmap = reader.read_next_long()?;

        let finder_info = reader.read_next_int_array(8)?;

        let raw_fork_data = reader.read_next_byte_array(400)?;

        Ok(HfsPlusVolumeHeader {
            signature,
            version,
            attributes,
            last_mounted_version,
            journal_info_block,
            create_date,
            modify_date,
            backup_date,
            checked_date,
            file_count,
            folder_count,
            block_size,
            total_blocks,
            free_blocks,
            next_allocation,
            rsrc_clump_size,
            data_clump_size,
            next_catalog_id,
            write_count,
            encodings_bitmap,
            finder_info,
            raw_fork_data,
        })
    }

    /// Returns true if the signature, version, and block size fields have valid values.
    pub fn is_valid(&self) -> bool {
        self.signature == HFSPLUS_SIGNATURE_MAGIC
            && self.version == HFSPLUS_VERSION
            && Self::is_good_block_size(self.block_size)
    }

    fn is_good_block_size(bs: i32) -> bool {
        bs > 0 && bs % 512 == 0
    }

    /// Returns true if `bp`'s length is at least `blockSize * totalBlocks` bytes.
    ///
    /// NOTE: can't compare with exact equals-to provider size because an extra 16 bytes are
    /// present in examples extracted from firmware images.
    ///
    /// Mirrors Java's `int * int` multiplication verbatim, including its 32-bit overflow
    /// wraparound, before widening to a 64-bit comparison.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading `bp`'s length fails.
    pub fn has_good_volume_info(&self, bp: &mut dyn ByteProvider) -> io::Result<bool> {
        let calculated_size = self.block_size.wrapping_mul(self.total_blocks) as i64;
        Ok(bp.length()? as i64 >= calculated_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
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

    /// Builds a well-formed 512 byte HFS+ volume header block, big-endian, with the given
    /// block size / total blocks (the fields exercised by [`HfsPlusVolumeHeader::is_valid`] and
    /// [`HfsPlusVolumeHeader::has_good_volume_info`]).
    fn valid_header_bytes(block_size: i32, total_blocks: i32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SIZEOF_HEADER as usize);
        buf.extend_from_slice(&HFSPLUS_SIGNATURE_MAGIC.to_be_bytes()); // signature
        buf.extend_from_slice(&HFSPLUS_VERSION.to_be_bytes()); // version
        buf.extend_from_slice(&0i32.to_be_bytes()); // attributes
        buf.extend_from_slice(&0i32.to_be_bytes()); // lastMountedVersion
        buf.extend_from_slice(&0i32.to_be_bytes()); // journalInfoBlock
        buf.extend_from_slice(&0i32.to_be_bytes()); // createDate
        buf.extend_from_slice(&0i32.to_be_bytes()); // modifyDate
        buf.extend_from_slice(&0i32.to_be_bytes()); // backupDate
        buf.extend_from_slice(&0i32.to_be_bytes()); // checkedDate
        buf.extend_from_slice(&0i32.to_be_bytes()); // fileCount
        buf.extend_from_slice(&0i32.to_be_bytes()); // folderCount
        buf.extend_from_slice(&block_size.to_be_bytes()); // blockSize
        buf.extend_from_slice(&total_blocks.to_be_bytes()); // totalBlocks
        buf.extend_from_slice(&0i32.to_be_bytes()); // freeBlocks
        buf.extend_from_slice(&0i32.to_be_bytes()); // nextAllocation
        buf.extend_from_slice(&0i32.to_be_bytes()); // rsrcClumpSize
        buf.extend_from_slice(&0i32.to_be_bytes()); // dataClumpSize
        buf.extend_from_slice(&0i32.to_be_bytes()); // nextCatalogID
        buf.extend_from_slice(&0i32.to_be_bytes()); // writeCount
        buf.extend_from_slice(&0i64.to_be_bytes()); // encodingsBitmap
        buf.extend_from_slice(&[0u8; 32]); // finderInfo (8 x i32)
        buf.extend_from_slice(&[0u8; 400]); // rawForkData
        assert_eq!(buf.len(), SIZEOF_HEADER as usize);
        buf
    }

    #[test]
    fn read_at_parses_all_fields_big_endian() {
        let data = valid_header_bytes(0x1000, 10);
        let mut reader = MockReader::new(data);

        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).expect("read_at should succeed");

        assert_eq!(header.signature, HFSPLUS_SIGNATURE_MAGIC);
        assert_eq!(header.version, HFSPLUS_VERSION);
        assert_eq!(header.block_size, 0x1000);
        assert_eq!(header.total_blocks, 10);
        assert_eq!(header.finder_info.len(), 8);
        assert_eq!(header.raw_fork_data.len(), 400);
    }

    #[test]
    fn read_at_forces_big_endian_regardless_of_reader_default() {
        let data = valid_header_bytes(0x1000, 10);
        let mut reader = MockReader::new(data);
        reader.set_little_endian(true);

        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).expect("read_at should succeed");

        assert_eq!(header.signature, HFSPLUS_SIGNATURE_MAGIC);
        assert!(reader.is_big_endian());
    }

    #[test]
    fn read_reads_from_default_offset() {
        let mut data = vec![0xAAu8; 1024];
        data.extend_from_slice(&valid_header_bytes(0x1000, 10));
        let mut reader = MockReader::new(data);

        let header = HfsPlusVolumeHeader::read(&mut reader).expect("read should succeed");

        assert!(header.is_valid());
        assert_eq!(reader.get_pointer_index(), 1024 + SIZEOF_HEADER);
    }

    #[test]
    fn is_valid_true_for_correct_signature_version_and_block_size() {
        let data = valid_header_bytes(0x1000, 10);
        let mut reader = MockReader::new(data);
        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).unwrap();

        assert!(header.is_valid());
    }

    #[test]
    fn is_valid_false_for_wrong_signature() {
        let mut data = valid_header_bytes(0x1000, 10);
        data[0..2].copy_from_slice(&0x0000i16.to_be_bytes());
        let mut reader = MockReader::new(data);
        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).unwrap();

        assert!(!header.is_valid());
    }

    #[test]
    fn is_valid_false_for_hfsx_version() {
        let mut data = valid_header_bytes(0x1000, 10);
        data[2..4].copy_from_slice(&HFSX_VERSION.to_be_bytes());
        let mut reader = MockReader::new(data);
        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).unwrap();

        assert!(!header.is_valid());
    }

    #[test]
    fn is_valid_false_for_bad_block_size() {
        let data = valid_header_bytes(100, 10); // not a multiple of 512
        let mut reader = MockReader::new(data);
        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).unwrap();

        assert!(!header.is_valid());
    }

    #[test]
    fn has_good_volume_info_true_when_provider_large_enough() {
        let data = valid_header_bytes(0x1000, 2);
        let mut reader = MockReader::new(data);
        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).unwrap();

        let mut bp = VecProvider(vec![0u8; 0x1000 * 2]);
        assert!(header.has_good_volume_info(&mut bp).unwrap());
    }

    #[test]
    fn has_good_volume_info_false_when_provider_too_small() {
        let data = valid_header_bytes(0x1000, 10);
        let mut reader = MockReader::new(data);
        let header = HfsPlusVolumeHeader::read_at(&mut reader, 0).unwrap();

        let mut bp = VecProvider(vec![0u8; 100]);
        assert!(!header.has_good_volume_info(&mut bp).unwrap());
    }

    #[test]
    fn probe_false_when_provider_too_short() {
        let data = vec![0u8; 100];
        let mut reader = MockReader::new(data);

        assert!(!HfsPlusVolumeHeader::probe(&mut reader));
    }

    #[test]
    fn probe_true_for_well_formed_volume() {
        let mut data = vec![0xAAu8; 1024];
        data.extend_from_slice(&valid_header_bytes(0x1000, 1));
        let mut reader = MockReader::new(data);

        assert!(HfsPlusVolumeHeader::probe(&mut reader));
    }

    #[test]
    fn probe_false_for_invalid_signature() {
        let mut header_bytes = valid_header_bytes(0x1000, 1);
        header_bytes[0..2].copy_from_slice(&0x0000i16.to_be_bytes());
        let mut data = vec![0xAAu8; 1024];
        data.extend_from_slice(&header_bytes);
        let mut reader = MockReader::new(data);

        assert!(!HfsPlusVolumeHeader::probe(&mut reader));
    }
}
