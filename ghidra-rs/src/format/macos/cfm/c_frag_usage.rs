use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Usage type for a Code Fragment Manager (CFM) fragment.
///
/// Specifies the purpose and role of a code fragment, such as whether it is an
/// application, library, extension, or stub.
/// Mirrors `CFragUsage` from the original Ghidra Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CFragUsage {
    /// Standard CFM import library.
    KImportLibraryCFrag,
    /// MacOS application.
    KApplicationCFrag,
    /// Application or library private extension/plug-in.
    KDropInAdditionCFrag,
    /// Import library used for linking only.
    KStubLibraryCFrag,
    /// Import library used for linking only and will be automatically weak linked.
    KWeakStubLibraryCFrag,
}

impl CFragUsage {
    /// Reads a single byte from the reader and returns the corresponding variant.
    ///
    /// # Errors
    /// Returns `Err` if reading from the reader fails, or if the byte value
    /// does not correspond to a valid `CFragUsage` variant.
    pub fn get(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_byte()? & 0xff;
        Self::find(value).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid CFragUsage value: {}", value),
            )
        })
    }

    /// Finds the variant corresponding to the given byte value.
    pub fn find(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::KImportLibraryCFrag),
            1 => Some(Self::KApplicationCFrag),
            2 => Some(Self::KDropInAdditionCFrag),
            3 => Some(Self::KStubLibraryCFrag),
            4 => Some(Self::KWeakStubLibraryCFrag),
            _ => None,
        }
    }

    /// Returns the byte value corresponding to this variant.
    pub fn value(self) -> u8 {
        match self {
            Self::KImportLibraryCFrag => 0,
            Self::KApplicationCFrag => 1,
            Self::KDropInAdditionCFrag => 2,
            Self::KStubLibraryCFrag => 3,
            Self::KWeakStubLibraryCFrag => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                position: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn is_valid_index(&self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }

        fn get_pointer_index(&self) -> u64 {
            self.position as u64
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.position;
            self.position = index as usize;
            old as u64
        }

        fn is_little_endian(&self) -> bool {
            false
        }

        fn set_little_endian(&mut self, _is_little_endian: bool) {}

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "index out of range"))
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start.checked_add(n_elements).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "overflow")
            })?;
            if end > self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "range out of bounds"));
            }
            Ok(self.bytes[start..end].to_vec())
        }

        fn get_byte_provider(
            &self,
        ) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            panic!("not implemented for mock")
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            let mut clone = Self {
                bytes: self.bytes.clone(),
                position: new_index as usize,
            };
            clone.position = new_index as usize;
            Box::new(clone)
        }
    }

    #[test]
    fn find_all_variants() {
        assert_eq!(CFragUsage::find(0), Some(CFragUsage::KImportLibraryCFrag));
        assert_eq!(CFragUsage::find(1), Some(CFragUsage::KApplicationCFrag));
        assert_eq!(CFragUsage::find(2), Some(CFragUsage::KDropInAdditionCFrag));
        assert_eq!(CFragUsage::find(3), Some(CFragUsage::KStubLibraryCFrag));
        assert_eq!(CFragUsage::find(4), Some(CFragUsage::KWeakStubLibraryCFrag));
    }

    #[test]
    fn find_invalid_variant() {
        assert_eq!(CFragUsage::find(5), None);
        assert_eq!(CFragUsage::find(255), None);
    }

    #[test]
    fn value_roundtrip() {
        let variants = [
            CFragUsage::KImportLibraryCFrag,
            CFragUsage::KApplicationCFrag,
            CFragUsage::KDropInAdditionCFrag,
            CFragUsage::KStubLibraryCFrag,
            CFragUsage::KWeakStubLibraryCFrag,
        ];

        for variant in &variants {
            let val = variant.value();
            assert_eq!(CFragUsage::find(val), Some(*variant));
        }
    }

    #[test]
    fn get_reads_byte() {
        let mut reader = MockReader::new(vec![0]);
        let result = CFragUsage::get(&mut reader);
        assert_eq!(result, Ok(CFragUsage::KImportLibraryCFrag));
        assert_eq!(reader.position, 1);
    }

    #[test]
    fn get_masks_byte() {
        let mut reader = MockReader::new(vec![0xFF]);
        let result = CFragUsage::get(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn get_all_variants() {
        let test_cases = [
            (0, CFragUsage::KImportLibraryCFrag),
            (1, CFragUsage::KApplicationCFrag),
            (2, CFragUsage::KDropInAdditionCFrag),
            (3, CFragUsage::KStubLibraryCFrag),
            (4, CFragUsage::KWeakStubLibraryCFrag),
        ];

        for (byte_val, expected) in &test_cases {
            let mut reader = MockReader::new(vec![*byte_val]);
            let result = CFragUsage::get(&mut reader);
            assert_eq!(result, Ok(*expected));
        }
    }

    #[test]
    fn copy_and_clone() {
        let original = CFragUsage::KApplicationCFrag;
        let copied = original;
        let cloned = original.clone();
        assert_eq!(original, copied);
        assert_eq!(original, cloned);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", CFragUsage::KImportLibraryCFrag),
            "KImportLibraryCFrag"
        );
        assert_eq!(
            format!("{:?}", CFragUsage::KWeakStubLibraryCFrag),
            "KWeakStubLibraryCFrag"
        );
    }

    #[test]
    fn variants_are_distinct() {
        let all = [
            CFragUsage::KImportLibraryCFrag,
            CFragUsage::KApplicationCFrag,
            CFragUsage::KDropInAdditionCFrag,
            CFragUsage::KStubLibraryCFrag,
            CFragUsage::KWeakStubLibraryCFrag,
        ];

        for i in 0..all.len() {
            for j in 0..all.len() {
                if i == j {
                    assert_eq!(all[i], all[j]);
                } else {
                    assert_ne!(all[i], all[j]);
                }
            }
        }
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(CFragUsage::KImportLibraryCFrag);
        set.insert(CFragUsage::KApplicationCFrag);
        set.insert(CFragUsage::KDropInAdditionCFrag);
        set.insert(CFragUsage::KStubLibraryCFrag);
        set.insert(CFragUsage::KWeakStubLibraryCFrag);

        assert_eq!(set.len(), 5);
    }
}
