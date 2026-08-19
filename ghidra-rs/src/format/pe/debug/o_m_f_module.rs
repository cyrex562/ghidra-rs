use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::debug::o_m_f_seg_desc::OmfSegDesc;

/// Represents the Object Module Format (OMF) module data structure.
///
/// Mirrors the `OMFModule` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct OMFModule {
///     unsigned short  ovlNumber;      // overlay number
///     unsigned short  iLib;           // library that the module was linked from
///     unsigned short  cSeg;           // count of number of segments in module
///     char            Style[2];       // debugging style "CV"
///     OMFSegDesc      SegInfo[1];     // describes segments in module
///     char            Name[];         // length prefixed module name padded to long word boundary
/// } OMFModule;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfModule {
    ovl_number: i16,
    i_lib: i16,
    c_seg: i16,
    style: i16,
    seg_desc_arr: Vec<OmfSegDesc>,
    name: String,
}

impl OmfModule {
    /// Creates a new `OmfModule` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `ptr` - The starting byte offset in the reader.
    /// * `_byte_count` - Mirrors the Java constructor's `byteCount` parameter,
    ///   which is likewise unused in the original constructor body.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &dyn BinaryReader, ptr: u64, _byte_count: i32) -> io::Result<Self> {
        let mut index = ptr;

        let ovl_number = reader.read_short(index)?;
        index += 2;
        let i_lib = reader.read_short(index)?;
        index += 2;
        let c_seg = reader.read_short(index)?;
        index += 2;
        let style = reader.read_short(index)?;
        index += 2;

        let seg_count = c_seg as u16 as usize;

        let mut seg_desc_arr = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            seg_desc_arr.push(OmfSegDesc::new(reader, index)?);
            index += OmfSegDesc::IMAGE_SIZEOF_OMF_SEG_DESC as u64;
        }

        index += 1;

        let name = reader.read_ascii_string(index)?;

        Ok(OmfModule {
            ovl_number,
            i_lib,
            c_seg,
            style,
            seg_desc_arr,
            name,
        })
    }

    /// Returns the overlay number.
    pub fn ovl_number(&self) -> i16 {
        self.ovl_number
    }

    /// Returns the library that the module was linked from.
    pub fn i_lib(&self) -> i16 {
        self.i_lib
    }

    /// Returns the debugging style, e.g. "CV".
    pub fn style(&self) -> i16 {
        self.style
    }

    /// Returns the module name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the OMF segment descriptions in this OMF module.
    pub fn omf_seg_descs(&self) -> &[OmfSegDesc] {
        &self.seg_desc_arr
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
            0x01, 0x00, // ovlNumber = 1
            0x02, 0x00, // iLib = 2
            0x00, 0x00, // cSeg = 0
            0x43, 0x56, // style = "CV"
            0xFF, // pad byte consumed before the name (mirrors the Java `++index`)
            b'h', b'i', 0x00, // name = "hi"
        ];

        let reader = MockReader::new(data, true);
        let module = OmfModule::new(&reader, 0, 0).expect("failed to read");

        assert_eq!(module.ovl_number(), 1);
        assert_eq!(module.i_lib(), 2);
        assert_eq!(module.style(), 0x5643);
        assert!(module.omf_seg_descs().is_empty());
        assert_eq!(module.name(), "hi");
    }

    #[test]
    fn read_structure_with_segments() {
        let mut data = vec![
            0x00, 0x00, // ovlNumber = 0
            0x00, 0x00, // iLib = 0
            0x02, 0x00, // cSeg = 2
            0x43, 0x56, // style = "CV"
        ];
        data.extend_from_slice(&[
            0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        ]);
        data.extend_from_slice(&[
            0x02, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        ]);
        data.push(0xFF); // pad byte consumed before the name
        data.extend_from_slice(b"mod\x00");

        let reader = MockReader::new(data, true);
        let module = OmfModule::new(&reader, 0, 0).expect("failed to read");

        assert_eq!(module.omf_seg_descs().len(), 2);
        assert_eq!(module.omf_seg_descs()[0].segment_index(), 1);
        assert_eq!(module.omf_seg_descs()[1].segment_index(), 2);
        assert_eq!(module.name(), "mod");
    }

    #[test]
    fn read_at_non_zero_offset() {
        let mut data = vec![0xAA; 4];
        data.extend_from_slice(&[
            0x05, 0x00, // ovlNumber = 5
            0x06, 0x00, // iLib = 6
            0x00, 0x00, // cSeg = 0
            0x43, 0x56, // style = "CV"
            0xFF, // pad byte
        ]);
        data.extend_from_slice(b"m\x00");

        let reader = MockReader::new(data, true);
        let module = OmfModule::new(&reader, 4, 0).expect("failed to read");

        assert_eq!(module.ovl_number(), 5);
        assert_eq!(module.i_lib(), 6);
        assert_eq!(module.name(), "m");
    }

    #[test]
    fn clone_and_equality() {
        let data = vec![
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x43, 0x56, 0xFF, b'a', 0x00,
        ];

        let reader = MockReader::new(data, true);
        let module1 = OmfModule::new(&reader, 0, 0).expect("failed to read");
        let module2 = module1.clone();

        assert_eq!(module1, module2);
    }
}
