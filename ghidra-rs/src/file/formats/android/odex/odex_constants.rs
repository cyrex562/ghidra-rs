use crate::app::util::bin::binary_reader::BinaryReader;

/// ODEX (OAT DEX) file format constants.
///
/// The ODEX format is used for optimized DEX files on Android, removed in Android 11.
///
/// Reference:
/// - <https://android.googlesource.com/platform/dalvik/+/refs/heads/kitkat-release/libdex/DexFile.h>
/// - <https://android.googlesource.com/platform/dalvik/+/refs/heads/lollipop-release/libdex/DexFile.h>
/// - <https://android.googlesource.com/platform/dalvik/+/refs/heads/marshmallow-release/libdex/DexFile.h>
/// - <https://android.googlesource.com/platform/dalvik/+/refs/heads/nougat-release/libdex/DexFile.h>
/// - <https://android.googlesource.com/platform/dalvik/+/refs/heads/oreo-release/libdex/DexFile.h>
/// - <https://android.googlesource.com/platform/dalvik/+/refs/heads/pie-release/libdex/DexFile.h>
/// - <https://android.googlesource.com/platform/dalvik/+/refs/heads/android10-release/libdex/DexFile.h>
///
/// Mirrors `ghidra.file.formats.android.odex.OdexConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OdexConstants;

impl OdexConstants {
    pub const ODEX_MAGIC_35: &'static str = "dey\n035\0";
    pub const ODEX_MAGIC_36: &'static str = "dey\n036\0";
    pub const ODEX_MAGIC_37: &'static str = "dey\n037\0";

    pub const ODEX_MAGIC_LENGTH: usize = 8;

    /// Checks if the given reader starts with an ODEX magic number.
    ///
    /// Returns true if the reader's contents start with ODEX_MAGIC_35 or ODEX_MAGIC_36.
    pub fn is_odex_file(reader: &dyn BinaryReader) -> bool {
        match reader.read_byte_array(0, Self::ODEX_MAGIC_LENGTH) {
            Ok(bytes) => {
                let magic = String::from_utf8_lossy(&bytes).into_owned();
                magic == Self::ODEX_MAGIC_35 || magic == Self::ODEX_MAGIC_36
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

    /// Minimal in-memory [`BinaryReader`] used to exercise the byte-array reads that
    /// [`OdexConstants::is_odex_file`] performs.
    struct MockReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, position: 0 }
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
            true
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
            let end = start
                .checked_add(n_elements)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
            if end > self.bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "range out of bounds",
                ));
            }
            Ok(self.bytes[start..end].to_vec())
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            panic!("not implemented for mock")
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(Self {
                bytes: self.bytes.clone(),
                position: new_index as usize,
            })
        }
    }

    #[test]
    fn magic_35_value() {
        assert_eq!(OdexConstants::ODEX_MAGIC_35, "dey\n035\0");
    }

    #[test]
    fn magic_36_value() {
        assert_eq!(OdexConstants::ODEX_MAGIC_36, "dey\n036\0");
    }

    #[test]
    fn magic_37_value() {
        assert_eq!(OdexConstants::ODEX_MAGIC_37, "dey\n037\0");
    }

    #[test]
    fn magic_length_matches_string_length() {
        assert_eq!(OdexConstants::ODEX_MAGIC_LENGTH, OdexConstants::ODEX_MAGIC_36.len());
        assert_eq!(OdexConstants::ODEX_MAGIC_LENGTH, 8);
    }

    #[test]
    fn all_magics_are_same_length() {
        assert_eq!(
            OdexConstants::ODEX_MAGIC_35.len(),
            OdexConstants::ODEX_MAGIC_LENGTH
        );
        assert_eq!(
            OdexConstants::ODEX_MAGIC_36.len(),
            OdexConstants::ODEX_MAGIC_LENGTH
        );
        assert_eq!(
            OdexConstants::ODEX_MAGIC_37.len(),
            OdexConstants::ODEX_MAGIC_LENGTH
        );
    }

    #[test]
    fn is_odex_file_with_magic_35() {
        let data = b"dey\n035\0extra data".to_vec();
        let reader = MockReader::new(data);

        assert!(OdexConstants::is_odex_file(&reader));
    }

    #[test]
    fn is_odex_file_with_magic_36() {
        let data = b"dey\n036\0extra data".to_vec();
        let reader = MockReader::new(data);

        assert!(OdexConstants::is_odex_file(&reader));
    }

    #[test]
    fn is_odex_file_with_magic_37_returns_false() {
        let data = b"dey\n037\0extra data".to_vec();
        let reader = MockReader::new(data);

        assert!(!OdexConstants::is_odex_file(&reader));
    }

    #[test]
    fn is_odex_file_with_short_data_returns_false() {
        let data = b"dey\n".to_vec();
        let reader = MockReader::new(data);

        assert!(!OdexConstants::is_odex_file(&reader));
    }

    #[test]
    fn is_odex_file_with_wrong_magic_returns_false() {
        let data = b"DEX\n035\0extra data".to_vec();
        let reader = MockReader::new(data);

        assert!(!OdexConstants::is_odex_file(&reader));
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(OdexConstants::default(), OdexConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = OdexConstants;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn magics_are_distinct() {
        assert_ne!(OdexConstants::ODEX_MAGIC_35, OdexConstants::ODEX_MAGIC_36);
        assert_ne!(OdexConstants::ODEX_MAGIC_36, OdexConstants::ODEX_MAGIC_37);
        assert_ne!(OdexConstants::ODEX_MAGIC_35, OdexConstants::ODEX_MAGIC_37);
    }
}
