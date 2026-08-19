use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// Locator kind for a Code Fragment Manager (CFM) fragment.
///
/// Represents the storage location and retrieval method for a CFM container.
/// Mirrors `CFragLocatorKind` from the original Ghidra Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CFragLocatorKind {
    /// Container is in memory.
    KMemoryCFragLocator,
    /// Container is in a file's data fork.
    KDataForkCFragLocator,
    /// Container is in a file's resource fork.
    KResourceCFragLocator,
    /// Reserved for possible future use.
    KNamedFragmentCFragLocator,
    /// Container is in the executable of a CFBundle.
    KCFBundleCFragLocator,
    /// Passed to init routines in lieu of kCFBundleCFragLocator.
    KCFBundlePreCFragLocator,
}

impl CFragLocatorKind {
    /// Reads a single byte from the reader and returns the corresponding variant.
    ///
    /// # Errors
    /// Returns `Err` if reading from the reader fails, or if the byte value
    /// does not correspond to a valid `CFragLocatorKind` variant.
    pub fn get(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let value = reader.read_next_byte()? & 0xff;
        Self::find(value).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid CFragLocatorKind value: {}", value),
            )
        })
    }

    /// Finds the variant corresponding to the given byte value.
    pub fn find(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::KMemoryCFragLocator),
            1 => Some(Self::KDataForkCFragLocator),
            2 => Some(Self::KResourceCFragLocator),
            3 => Some(Self::KNamedFragmentCFragLocator),
            4 => Some(Self::KCFBundleCFragLocator),
            5 => Some(Self::KCFBundlePreCFragLocator),
            _ => None,
        }
    }

    /// Returns the byte value corresponding to this variant.
    pub fn value(self) -> u8 {
        match self {
            Self::KMemoryCFragLocator => 0,
            Self::KDataForkCFragLocator => 1,
            Self::KResourceCFragLocator => 2,
            Self::KNamedFragmentCFragLocator => 3,
            Self::KCFBundleCFragLocator => 4,
            Self::KCFBundlePreCFragLocator => 5,
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
        assert_eq!(CFragLocatorKind::find(0), Some(CFragLocatorKind::KMemoryCFragLocator));
        assert_eq!(
            CFragLocatorKind::find(1),
            Some(CFragLocatorKind::KDataForkCFragLocator)
        );
        assert_eq!(
            CFragLocatorKind::find(2),
            Some(CFragLocatorKind::KResourceCFragLocator)
        );
        assert_eq!(
            CFragLocatorKind::find(3),
            Some(CFragLocatorKind::KNamedFragmentCFragLocator)
        );
        assert_eq!(
            CFragLocatorKind::find(4),
            Some(CFragLocatorKind::KCFBundleCFragLocator)
        );
        assert_eq!(
            CFragLocatorKind::find(5),
            Some(CFragLocatorKind::KCFBundlePreCFragLocator)
        );
    }

    #[test]
    fn find_invalid_variant() {
        assert_eq!(CFragLocatorKind::find(6), None);
        assert_eq!(CFragLocatorKind::find(255), None);
    }

    #[test]
    fn value_roundtrip() {
        let variants = [
            CFragLocatorKind::KMemoryCFragLocator,
            CFragLocatorKind::KDataForkCFragLocator,
            CFragLocatorKind::KResourceCFragLocator,
            CFragLocatorKind::KNamedFragmentCFragLocator,
            CFragLocatorKind::KCFBundleCFragLocator,
            CFragLocatorKind::KCFBundlePreCFragLocator,
        ];

        for variant in &variants {
            let val = variant.value();
            assert_eq!(CFragLocatorKind::find(val), Some(*variant));
        }
    }

    #[test]
    fn get_reads_byte() {
        let mut reader = MockReader::new(vec![0]);
        let result = CFragLocatorKind::get(&mut reader);
        assert_eq!(result.unwrap(), CFragLocatorKind::KMemoryCFragLocator);
        assert_eq!(reader.position, 1);
    }

    #[test]
    fn get_masks_byte() {
        let mut reader = MockReader::new(vec![0xFF]);
        let result = CFragLocatorKind::get(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn get_all_variants() {
        let test_cases = [
            (0, CFragLocatorKind::KMemoryCFragLocator),
            (1, CFragLocatorKind::KDataForkCFragLocator),
            (2, CFragLocatorKind::KResourceCFragLocator),
            (3, CFragLocatorKind::KNamedFragmentCFragLocator),
            (4, CFragLocatorKind::KCFBundleCFragLocator),
            (5, CFragLocatorKind::KCFBundlePreCFragLocator),
        ];

        for (byte_val, expected) in &test_cases {
            let mut reader = MockReader::new(vec![*byte_val]);
            let result = CFragLocatorKind::get(&mut reader);
            assert_eq!(result.unwrap(), *expected);
        }
    }

    #[test]
    fn copy_and_clone() {
        let original = CFragLocatorKind::KDataForkCFragLocator;
        let copied = original;
        let cloned = original.clone();
        assert_eq!(original, copied);
        assert_eq!(original, cloned);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", CFragLocatorKind::KMemoryCFragLocator),
            "KMemoryCFragLocator"
        );
        assert_eq!(
            format!("{:?}", CFragLocatorKind::KCFBundlePreCFragLocator),
            "KCFBundlePreCFragLocator"
        );
    }

    #[test]
    fn variants_are_distinct() {
        let all = [
            CFragLocatorKind::KMemoryCFragLocator,
            CFragLocatorKind::KDataForkCFragLocator,
            CFragLocatorKind::KResourceCFragLocator,
            CFragLocatorKind::KNamedFragmentCFragLocator,
            CFragLocatorKind::KCFBundleCFragLocator,
            CFragLocatorKind::KCFBundlePreCFragLocator,
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
        set.insert(CFragLocatorKind::KMemoryCFragLocator);
        set.insert(CFragLocatorKind::KDataForkCFragLocator);
        set.insert(CFragLocatorKind::KResourceCFragLocator);
        set.insert(CFragLocatorKind::KNamedFragmentCFragLocator);
        set.insert(CFragLocatorKind::KCFBundleCFragLocator);
        set.insert(CFragLocatorKind::KCFBundlePreCFragLocator);

        assert_eq!(set.len(), 6);
    }
}
