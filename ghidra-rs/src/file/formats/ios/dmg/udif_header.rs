use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// Magic value `'koly'` (`0x6b6f6c79`) marking the start of a valid [`UdifHeader`].
const SIGNATURE_MAGIC_KOLY: i32 = 0x6b6f_6c79;

/// Size, in bytes, of a UDIF header block.
const SIZEOF_UDIF_HEADER: u64 = 512;

/// Apple Universal Disk Image Format header block, typically located at end of `.dmg` files.
///
/// Mirrors `ghidra.file.formats.ios.dmg.UDIFHeader`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdifHeader {
    signature: i32,
    version: i32,
    header_size: i32,
    flags: i32,
    running_data_fork_offset: i64,
    data_fork_offset: i64,
    data_fork_length: i64,
    rsrc_fork_offset: i64,
    rsrc_fork_length: i64,
    segment_number: i32,
    segment_count: i32,
    segment_id: Vec<u8>,
    data_checksum_type: i32,
    data_checksum_size: i32,
    data_checksum: Vec<i32>,
    xml_offset: i64,
    xml_length: i64,
    reserved: Vec<u8>,
    checksum_type: i32,
    checksum_size: i32,
    checksum: Vec<i32>,
    image_variant: i32,
    sector_count: i64,
    reserved2: i32,
    reserved3: i32,
    reserved4: i32,
}

impl UdifHeader {
    /// Reads a [`UdifHeader`] from the end of the underlying byte provider of `reader`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from `reader` fails.
    pub fn read(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let offset = reader.length()? - SIZEOF_UDIF_HEADER;
        Self::read_at(reader, offset)
    }

    /// Reads a [`UdifHeader`] from the specified offset of `reader` (typically 512 bytes from
    /// the end of the underlying byte provider).
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from `reader` fails.
    pub fn read_at(reader: &mut dyn BinaryReader, offset: u64) -> io::Result<Self> {
        reader.set_little_endian(false);
        reader.set_pointer_index(offset);

        let signature = reader.read_next_int()?;
        let version = reader.read_next_int()?;
        let header_size = reader.read_next_int()?;
        let flags = reader.read_next_int()?;
        let running_data_fork_offset = reader.read_next_long()?;
        let data_fork_offset = reader.read_next_long()?;
        let data_fork_length = reader.read_next_long()?;
        let rsrc_fork_offset = reader.read_next_long()?;
        let rsrc_fork_length = reader.read_next_long()?;
        let segment_number = reader.read_next_int()?;
        let segment_count = reader.read_next_int()?;
        let segment_id = reader.read_next_byte_array(16)?;
        let data_checksum_type = reader.read_next_int()?;
        let data_checksum_size = reader.read_next_int()?;
        let data_checksum = reader.read_next_int_array(32)?;
        let xml_offset = reader.read_next_long()?;
        let xml_length = reader.read_next_long()?;
        let reserved = reader.read_next_byte_array(120)?;
        let checksum_type = reader.read_next_int()?;
        let checksum_size = reader.read_next_int()?;
        let checksum = reader.read_next_int_array(32)?;
        let image_variant = reader.read_next_int()?;
        let sector_count = reader.read_next_long()?;
        let reserved2 = reader.read_next_int()?;
        let reserved3 = reader.read_next_int()?;
        let reserved4 = reader.read_next_int()?;

        Ok(UdifHeader {
            signature,
            version,
            header_size,
            flags,
            running_data_fork_offset,
            data_fork_offset,
            data_fork_length,
            rsrc_fork_offset,
            rsrc_fork_length,
            segment_number,
            segment_count,
            segment_id,
            data_checksum_type,
            data_checksum_size,
            data_checksum,
            xml_offset,
            xml_length,
            reserved,
            checksum_type,
            checksum_size,
            checksum,
            image_variant,
            sector_count,
            reserved2,
            reserved3,
            reserved4,
        })
    }

    /// Returns true if the fixed fields have valid values.
    pub fn is_valid(&self) -> bool {
        self.signature == SIGNATURE_MAGIC_KOLY && self.header_size as u64 == SIZEOF_UDIF_HEADER
    }

    /// Returns true if the file offset values in the header are within bounds of `bp`.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading `bp`'s length fails.
    pub fn has_good_offsets(&self, bp: &mut dyn ByteProvider) -> io::Result<bool> {
        let length = bp.length()? as i64;
        Ok(0 <= self.data_fork_offset
            && self.data_fork_offset < length
            && self.data_fork_length > 0
            && self.data_fork_offset + self.data_fork_length < length
            && 0 <= self.xml_offset
            && self.xml_offset < length
            && self.xml_length > 0
            && self.xml_offset + self.xml_length < length)
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

    /// Builds a well-formed 512 byte UDIF header block, big-endian, with the given fork/xml
    /// offsets and lengths (the fields exercised by [`UdifHeader::has_good_offsets`]).
    fn valid_header_bytes(data_fork_offset: i64, data_fork_length: i64, xml_offset: i64, xml_length: i64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SIZEOF_UDIF_HEADER as usize);
        buf.extend_from_slice(&SIGNATURE_MAGIC_KOLY.to_be_bytes()); // signature
        buf.extend_from_slice(&4i32.to_be_bytes()); // version
        buf.extend_from_slice(&(SIZEOF_UDIF_HEADER as i32).to_be_bytes()); // headerSize
        buf.extend_from_slice(&0i32.to_be_bytes()); // flags
        buf.extend_from_slice(&0i64.to_be_bytes()); // runningDataForkOffset
        buf.extend_from_slice(&data_fork_offset.to_be_bytes()); // dataForkOffset
        buf.extend_from_slice(&data_fork_length.to_be_bytes()); // dataForkLength
        buf.extend_from_slice(&0i64.to_be_bytes()); // rsrcForkOffset
        buf.extend_from_slice(&0i64.to_be_bytes()); // rsrcForkLength
        buf.extend_from_slice(&0i32.to_be_bytes()); // segmentNumber
        buf.extend_from_slice(&1i32.to_be_bytes()); // segmentCount
        buf.extend_from_slice(&[0u8; 16]); // segmentID
        buf.extend_from_slice(&0i32.to_be_bytes()); // dataChecksumType
        buf.extend_from_slice(&0i32.to_be_bytes()); // dataChecksumSize
        buf.extend_from_slice(&[0u8; 128]); // dataChecksum (32 x i32)
        buf.extend_from_slice(&xml_offset.to_be_bytes()); // xmlOffset
        buf.extend_from_slice(&xml_length.to_be_bytes()); // xmlLength
        buf.extend_from_slice(&[0u8; 120]); // reserved
        buf.extend_from_slice(&0i32.to_be_bytes()); // checksumType
        buf.extend_from_slice(&0i32.to_be_bytes()); // checksumSize
        buf.extend_from_slice(&[0u8; 128]); // checksum (32 x i32)
        buf.extend_from_slice(&0i32.to_be_bytes()); // imageVariant
        buf.extend_from_slice(&0i64.to_be_bytes()); // sectorCount
        buf.extend_from_slice(&0i32.to_be_bytes()); // reserved2
        buf.extend_from_slice(&0i32.to_be_bytes()); // reserved3
        buf.extend_from_slice(&0i32.to_be_bytes()); // reserved4
        assert_eq!(buf.len(), SIZEOF_UDIF_HEADER as usize);
        buf
    }

    #[test]
    fn read_at_parses_all_fields_big_endian() {
        let data = valid_header_bytes(0, 100, 100, 50);
        let mut reader = MockReader::new(data);

        let header = UdifHeader::read_at(&mut reader, 0).expect("read_at should succeed");

        assert_eq!(header.signature, SIGNATURE_MAGIC_KOLY);
        assert_eq!(header.version, 4);
        assert_eq!(header.header_size as u64, SIZEOF_UDIF_HEADER);
        assert_eq!(header.segment_count, 1);
        assert_eq!(header.segment_id.len(), 16);
        assert_eq!(header.data_checksum.len(), 32);
        assert_eq!(header.reserved.len(), 120);
        assert_eq!(header.checksum.len(), 32);
        assert_eq!(header.data_fork_offset, 0);
        assert_eq!(header.data_fork_length, 100);
        assert_eq!(header.xml_offset, 100);
        assert_eq!(header.xml_length, 50);
    }

    #[test]
    fn read_at_forces_big_endian_regardless_of_reader_default() {
        let data = valid_header_bytes(0, 100, 100, 50);
        let mut reader = MockReader::new(data);
        reader.set_little_endian(true);

        let header = UdifHeader::read_at(&mut reader, 0).expect("read_at should succeed");

        assert_eq!(header.signature, SIGNATURE_MAGIC_KOLY);
        assert!(reader.is_big_endian());
    }

    #[test]
    fn read_reads_from_end_of_provider() {
        let mut data = vec![0xAAu8; 128];
        data.extend_from_slice(&valid_header_bytes(0, 100, 100, 50));
        let total_len = data.len() as u64;
        let mut reader = MockReader::new(data);

        let header = UdifHeader::read(&mut reader).expect("read should succeed");

        assert!(header.is_valid());
        assert_eq!(reader.get_pointer_index(), total_len);
    }

    #[test]
    fn is_valid_true_for_correct_signature_and_size() {
        let data = valid_header_bytes(0, 100, 100, 50);
        let mut reader = MockReader::new(data);
        let header = UdifHeader::read_at(&mut reader, 0).unwrap();

        assert!(header.is_valid());
    }

    #[test]
    fn is_valid_false_for_wrong_signature() {
        let mut data = valid_header_bytes(0, 100, 100, 50);
        data[0] = 0x00; // corrupt signature
        let mut reader = MockReader::new(data);
        let header = UdifHeader::read_at(&mut reader, 0).unwrap();

        assert!(!header.is_valid());
    }

    #[test]
    fn is_valid_false_for_wrong_header_size() {
        let mut data = valid_header_bytes(0, 100, 100, 50);
        data[8..12].copy_from_slice(&256i32.to_be_bytes());
        let mut reader = MockReader::new(data);
        let header = UdifHeader::read_at(&mut reader, 0).unwrap();

        assert!(!header.is_valid());
    }

    #[test]
    fn has_good_offsets_true_when_within_bounds() {
        let mut backing = vec![0u8; 1024];
        let header_bytes = valid_header_bytes(0, 100, 100, 50);
        backing[512..].copy_from_slice(&header_bytes);
        let mut reader = MockReader::new(backing.clone());
        let header = UdifHeader::read_at(&mut reader, 512).unwrap();

        let mut bp = VecProvider(backing);
        assert!(header.has_good_offsets(&mut bp).unwrap());
    }

    #[test]
    fn has_good_offsets_false_when_data_fork_out_of_bounds() {
        let backing = vec![0u8; 1024];
        let header_bytes = valid_header_bytes(2000, 100, 100, 50);
        let mut reader = MockReader::new(header_bytes);
        let header = UdifHeader::read_at(&mut reader, 0).unwrap();

        let mut bp = VecProvider(backing);
        assert!(!header.has_good_offsets(&mut bp).unwrap());
    }

    #[test]
    fn has_good_offsets_false_when_xml_length_is_zero() {
        let mut backing = vec![0u8; 1024];
        let header_bytes = valid_header_bytes(0, 100, 100, 0);
        backing[512..].copy_from_slice(&header_bytes);
        let mut reader = MockReader::new(backing.clone());
        let header = UdifHeader::read_at(&mut reader, 512).unwrap();

        let mut bp = VecProvider(backing);
        assert!(!header.has_good_offsets(&mut bp).unwrap());
    }

    #[test]
    fn has_good_offsets_false_when_negative_offset() {
        let backing = vec![0u8; 1024];
        let header_bytes = valid_header_bytes(-1, 100, 100, 50);
        let mut reader = MockReader::new(header_bytes);
        let header = UdifHeader::read_at(&mut reader, 0).unwrap();

        let mut bp = VecProvider(backing);
        assert!(!header.has_good_offsets(&mut bp).unwrap());
    }
}
