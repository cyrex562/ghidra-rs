use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::debug::o_m_f_src_module_file::OmfSrcModuleFile;

/// Represents the Object Module Format (OMF) Source Module data structure.
///
/// Mirrors the `OMFSrcModule` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// short cFile        - Number of source files contributing code to segments
/// short cSeg         - Number of code segments receiving code from module
/// int [] baseSrcFile - An array of base offsets
/// int [] starts      - start offset within the segment of the first byte of code from the module
/// int [] ends        - ending address of code from the module
/// short [] segs      - Array of segment indicies that receive code from the module
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfSrcModule {
    c_file: i16,
    c_seg: i16,
    base_src_file: Vec<i32>,
    starts: Vec<i32>,
    ends: Vec<i32>,
    segs: Vec<i16>,
    module_file_list: Vec<OmfSrcModuleFile>,
}

impl OmfSrcModule {
    /// Creates a new `OmfSrcModule` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, ptr: u64) -> io::Result<Self> {
        let mut index = ptr;

        let c_file = reader.read_short(index)?;
        index += 2;
        let c_seg = reader.read_short(index)?;
        index += 2;

        let file_count = c_file as u16 as usize;
        let seg_count = c_seg as u16 as usize;

        let mut base_src_file = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            base_src_file.push(reader.read_int(index)?);
            index += 4;
        }

        let mut starts = Vec::with_capacity(seg_count);
        let mut ends = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            starts.push(reader.read_int(index)?);
            index += 4;
            ends.push(reader.read_int(index)?);
            index += 4;
        }

        let mut segs = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            segs.push(reader.read_short(index)?);
            index += 2;
        }

        let mut module_file_list = Vec::with_capacity(file_count);
        for base in base_src_file.iter().take(file_count) {
            let file_ptr = (ptr as i64).wrapping_add(*base as i64) as u64;
            module_file_list.push(OmfSrcModuleFile::new(reader, ptr as i32, file_ptr)?);
        }

        Ok(OmfSrcModule {
            c_file,
            c_seg,
            base_src_file,
            starts,
            ends,
            segs,
            module_file_list,
        })
    }

    /// Returns the array of source files.
    pub fn omf_src_module_files(&self) -> &[OmfSrcModuleFile] {
        &self.module_file_list
    }

    /// Returns an array of base offsets.
    pub fn base_src_file(&self) -> &[i32] {
        &self.base_src_file
    }

    /// Returns the number of source files contributing code to segments.
    pub fn file_count(&self) -> i16 {
        self.c_file
    }

    /// Returns the number of code segments receiving code from module.
    pub fn segment_count(&self) -> i16 {
        self.c_seg
    }

    /// Returns an array of ending addresses of code from the module.
    pub fn ends(&self) -> &[i32] {
        &self.ends
    }

    /// Returns an array of segment indicies that receive code from the module.
    pub fn segments(&self) -> &[i16] {
        &self.segs
    }

    /// Returns an array of start offsets within the segment of the first byte of code
    /// from the module.
    pub fn starts(&self) -> &[i32] {
        &self.starts
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
    fn read_structure_with_no_files_or_segments() {
        let data = vec![
            0x00, 0x00, // cFile = 0
            0x00, 0x00, // cSeg = 0
        ];

        let reader = MockReader::new(data, true);
        let module = OmfSrcModule::new(&reader, 0).expect("failed to read");

        assert_eq!(module.file_count(), 0);
        assert_eq!(module.segment_count(), 0);
        assert!(module.base_src_file().is_empty());
        assert!(module.starts().is_empty());
        assert!(module.ends().is_empty());
        assert!(module.segments().is_empty());
        assert!(module.omf_src_module_files().is_empty());
    }

    #[test]
    fn read_structure_with_one_file_and_one_segment() {
        let mut data = vec![
            0x01, 0x00, // cFile = 1
            0x01, 0x00, // cSeg = 1
        ];
        data.extend_from_slice(&[0x12, 0x00, 0x00, 0x00]); // baseSrcFile[0] = 0x12
        data.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]); // starts[0] = 0x20
        data.extend_from_slice(&[0x30, 0x00, 0x00, 0x00]); // ends[0] = 0x30
        data.extend_from_slice(&[0x05, 0x00]); // segs[0] = 5

        // The 18-byte (0x12) header above is immediately followed by the
        // OMFSrcModuleFile, so baseSrcFile[0] (0x12) points at absolute offset 0x12.
        while data.len() < 0x12 {
            data.push(0xFF);
        }
        data.extend_from_slice(&[
            0x00, 0x00, // cSeg = 0
            0x00, 0x00, // pad = 0
            0x03, b'f', b'o', b'o', // cbName = 3, name = "foo"
        ]);

        let reader = MockReader::new(data, true);
        let module = OmfSrcModule::new(&reader, 0).expect("failed to read");

        assert_eq!(module.file_count(), 1);
        assert_eq!(module.segment_count(), 1);
        assert_eq!(module.base_src_file(), &[0x12]);
        assert_eq!(module.starts(), &[0x20]);
        assert_eq!(module.ends(), &[0x30]);
        assert_eq!(module.segments(), &[5]);

        let files = module.omf_src_module_files();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name(), "foo");
    }

    #[test]
    fn read_at_non_zero_offset() {
        let mut data = vec![0xAA; 4];
        data.extend_from_slice(&[
            0x00, 0x00, // cFile = 0
            0x00, 0x00, // cSeg = 0
        ]);

        let reader = MockReader::new(data, true);
        let module = OmfSrcModule::new(&reader, 4).expect("failed to read");

        assert_eq!(module.file_count(), 0);
        assert_eq!(module.segment_count(), 0);
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x00, 0x00, // cFile = 0
            0x00, 0x00, // cSeg = 0
        ];

        let reader = MockReader::new(data, true);
        let module1 = OmfSrcModule::new(&reader, 0).expect("failed to read");
        let module2 = module1.clone();

        assert_eq!(module1, module2);
    }
}
