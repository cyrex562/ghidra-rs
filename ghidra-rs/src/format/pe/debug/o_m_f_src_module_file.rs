use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::debug::o_m_f_src_module_line::OmfSrcModuleLine;

/// Represents the Object Module Format (OMF) Source Module File data structure.
///
/// Mirrors the `OMFSrcModuleFile` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// Describes the code segments that receive code from a source file.
///
/// ```text
/// short cSeg        - Number of segments that receive code from the source file.
/// short pad         - pad field to maintain alignment
/// int [] baseSrcLn  - array of offsets for the line or address mapping for each segment
///                     that receives code from the source file.
/// int [] starts     - starting addresses within the segment of the first byte of code
///                     from the module.
/// int [] ends       - ending addresses of the code from the module.
/// byte cbName       - count or number of bytes in source file name.
/// String name       - name of source file.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfSrcModuleFile {
    c_seg: i16,
    pad: i16,
    base_src_ln: Vec<i32>,
    starts: Vec<i32>,
    ends: Vec<i32>,
    cb_name: u8,
    name: String,
    module_line_list: Vec<OmfSrcModuleLine>,
}

impl OmfSrcModuleFile {
    /// Creates a new `OmfSrcModuleFile` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `module_base` - The base offset of the module, added to each `baseSrcLn` entry
    ///   to locate the corresponding `OMFSrcModuleLine` structure.
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, module_base: i32, ptr: u64) -> io::Result<Self> {
        let mut index = ptr;

        let c_seg = reader.read_short(index)?;
        index += 2;
        let pad = reader.read_short(index)?;
        index += 2;

        let seg_count = c_seg as u16 as usize;

        let mut base_src_ln = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            base_src_ln.push(reader.read_int(index)?);
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

        let cb_name = reader.read_byte(index)?;
        index += 1;

        let name = reader.read_ascii_string_fixed(index, cb_name as usize)?;
        index += cb_name as u64;

        let mut module_line_list = Vec::with_capacity(seg_count);
        for base in base_src_ln.iter().take(seg_count) {
            let line_ptr = (module_base.wrapping_add(*base)) as i64 as u64;
            let line = OmfSrcModuleLine::new(reader, line_ptr)?;
            index += line.byte_count() as u64;
            module_line_list.push(line);
        }

        Ok(OmfSrcModuleFile {
            c_seg,
            pad,
            base_src_ln,
            starts,
            ends,
            cb_name,
            name,
            module_line_list,
        })
    }

    /// Returns the source module lines.
    pub fn omf_src_module_lines(&self) -> &[OmfSrcModuleLine] {
        &self.module_line_list
    }

    /// Returns the array of offsets for the line or address mapping for each segment
    /// that receives code from the source file.
    pub fn base_src_ln(&self) -> &[i32] {
        &self.base_src_ln
    }

    /// Returns the number of segments that receive code from the source file.
    pub fn segment_count(&self) -> i16 {
        self.c_seg
    }

    /// Returns the ending addresses of the code from the module.
    pub fn ends(&self) -> &[i32] {
        &self.ends
    }

    /// Returns the name of the source file.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the pad field used to maintain alignment.
    pub fn pad(&self) -> i16 {
        self.pad
    }

    /// Returns the starting addresses within the segment of the first byte of code from
    /// the module.
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
    fn read_structure_with_no_segments() {
        let data = vec![
            0x00, 0x00, // cSeg = 0
            0x00, 0x00, // pad = 0
            0x03, b'f', b'o', b'o', // cbName = 3, name = "foo"
        ];

        let reader = MockReader::new(data, true);
        let file = OmfSrcModuleFile::new(&reader, 0, 0).expect("failed to read");

        assert_eq!(file.segment_count(), 0);
        assert_eq!(file.pad(), 0);
        assert!(file.base_src_ln().is_empty());
        assert!(file.starts().is_empty());
        assert!(file.ends().is_empty());
        assert_eq!(file.name(), "foo");
        assert!(file.omf_src_module_lines().is_empty());
    }

    #[test]
    fn read_structure_with_one_segment() {
        let mut data = vec![
            0x01, 0x00, // cSeg = 1
            0xAB, 0xCD, // pad
        ];
        data.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // baseSrcLn[0] = 0x14
        data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // starts[0] = 0x10
        data.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]); // ends[0] = 0x20
        data.push(0x03); // cbName = 3
        data.extend_from_slice(b"bar"); // name

        // baseSrcLn[0] (0x14) points to an OMFSrcModuleLine at absolute offset 0x14.
        while data.len() < 0x14 {
            data.push(0xFF);
        }
        data.extend_from_slice(&[
            0x02, 0x00, // seg = 2
            0x00, 0x00, // cPair = 0
        ]);

        let reader = MockReader::new(data, true);
        let file = OmfSrcModuleFile::new(&reader, 0, 0).expect("failed to read");

        assert_eq!(file.segment_count(), 1);
        assert_eq!(file.pad(), -12885); // 0xCDAB as a signed short
        assert_eq!(file.base_src_ln(), &[0x14]);
        assert_eq!(file.starts(), &[0x10]);
        assert_eq!(file.ends(), &[0x20]);
        assert_eq!(file.name(), "bar");

        let lines = file.omf_src_module_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].segment_index(), 2);
        assert_eq!(lines[0].pair_count(), 0);
    }

    #[test]
    fn read_with_nonzero_module_base() {
        let mut data = vec![
            0x01, 0x00, // cSeg = 1
            0x00, 0x00, // pad = 0
        ];
        data.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // baseSrcLn[0] = 8
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // starts[0] = 0
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ends[0] = 0
        data.push(0x01); // cbName = 1
        data.extend_from_slice(b"x"); // name

        // moduleBase (0x10) + baseSrcLn[0] (8) = offset 0x18.
        while data.len() < 0x18 {
            data.push(0xFF);
        }
        data.extend_from_slice(&[
            0x05, 0x00, // seg = 5
            0x00, 0x00, // cPair = 0
        ]);

        let reader = MockReader::new(data, true);
        let file = OmfSrcModuleFile::new(&reader, 0x10, 0).expect("failed to read");

        let lines = file.omf_src_module_lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].segment_index(), 5);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let mut data = vec![0xAA; 4];
        data.extend_from_slice(&[
            0x00, 0x00, // cSeg = 0
            0x00, 0x00, // pad = 0
            0x02, b'h', b'i', // cbName = 2, name = "hi"
        ]);

        let reader = MockReader::new(data, true);
        let file = OmfSrcModuleFile::new(&reader, 0, 4).expect("failed to read");

        assert_eq!(file.segment_count(), 0);
        assert_eq!(file.name(), "hi");
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x00, 0x00, // cSeg = 0
            0x00, 0x00, // pad = 0
            0x01, b'a', // cbName = 1, name = "a"
        ];

        let reader = MockReader::new(data, true);
        let file1 = OmfSrcModuleFile::new(&reader, 0, 0).expect("failed to read");
        let file2 = file1.clone();

        assert_eq!(file1, file2);
    }
}
