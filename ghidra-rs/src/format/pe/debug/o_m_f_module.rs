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
    pub fn new(reader: &BinaryReader, ptr: u64, _byte_count: i32) -> io::Result<Self> {
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

        let reader = BinaryReader::from_bytes(data, true);
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

        let reader = BinaryReader::from_bytes(data, true);
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

        let reader = BinaryReader::from_bytes(data, true);
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

        let reader = BinaryReader::from_bytes(data, true);
        let module1 = OmfModule::new(&reader, 0, 0).expect("failed to read");
        let module2 = module1.clone();

        assert_eq!(module1, module2);
    }
}
