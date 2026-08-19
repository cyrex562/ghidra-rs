use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// Constants describing the Android DEX (Dalvik Executable) file format.
///
/// References:
/// - <https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file.h>
/// - <https://android.googlesource.com/platform/art/+/master/libdexfile/dex/standard_dex_file.cc>
///
/// Mirrors `ghidra.file.formats.android.dex.format.DexConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DexConstants;

impl DexConstants {
    pub const DEX_MAGIC_BASE: &'static str = "dex\n";

    pub const DEX_VERSION_LENGTH: i32 = 4;

    pub const DEX_VERSION_009: &'static str = "009";

    /// Expected version string
    pub const DEX_VERSION_035: &'static str = "035";
    /// Dex version 036 skipped because of an old dalvik bug on some versions
    /// of android where dex files with that version number would erroneously
    /// be accepted and run.
    pub const DEX_VERSION_036: &'static str = "036";
    /// V037 was introduced in API LEVEL 24
    pub const DEX_VERSION_037: &'static str = "037";
    /// Dex version 038: Android "O" and beyond.
    ///
    /// V038 was introduced in API LEVEL 26
    pub const DEX_VERSION_038: &'static str = "038";
    /// Dex version 039: Android "P" and beyond.
    ///
    /// V039 was introduced in API LEVEL 28
    pub const DEX_VERSION_039: &'static str = "039";
    /// Dex version 040: beyond Android "10" (previously known as Android "Q").
    pub const DEX_VERSION_040: &'static str = "040";

    pub const MACHINE: &'static str = "1";

    pub const ENDIAN_CONSTANT: u32 = 0x12345678;
    pub const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

    pub const K_DEX_ENDIAN_CONSTANT: u32 = 0x12345678;

    /// First Dex format version enforcing class definition ordering rules.
    pub const K_CLASS_DEFINITION_ORDER_ENFORCED_VERSION: i32 = 37;

    pub const K_SHA1_DIGEST_SIZE: i32 = 20;

    /// Returns true if the bytes at the start of `provider` match [`Self::DEX_MAGIC_BASE`].
    pub fn is_dex_file(provider: &mut dyn ByteProvider) -> bool {
        match provider.read_bytes(0, Self::DEX_MAGIC_BASE.len()) {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(s) => s == Self::DEX_MAGIC_BASE,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct VecProvider {
        data: Vec<u8>,
    }

    impl VecProvider {
        fn new(data: &[u8]) -> Self {
            VecProvider { data: data.to_vec() }
        }
    }

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.data.len()
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.data
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start.checked_add(length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "overflow")
            })?;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            Ok(self.data[start..end].to_vec())
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    #[test]
    fn dex_magic_base_value() {
        assert_eq!(DexConstants::DEX_MAGIC_BASE, "dex\n");
    }

    #[test]
    fn dex_version_length_value() {
        assert_eq!(DexConstants::DEX_VERSION_LENGTH, 4);
    }

    #[test]
    fn version_constants() {
        assert_eq!(DexConstants::DEX_VERSION_009, "009");
        assert_eq!(DexConstants::DEX_VERSION_035, "035");
        assert_eq!(DexConstants::DEX_VERSION_036, "036");
        assert_eq!(DexConstants::DEX_VERSION_037, "037");
        assert_eq!(DexConstants::DEX_VERSION_038, "038");
        assert_eq!(DexConstants::DEX_VERSION_039, "039");
        assert_eq!(DexConstants::DEX_VERSION_040, "040");
    }

    #[test]
    fn machine_value() {
        assert_eq!(DexConstants::MACHINE, "1");
    }

    #[test]
    fn endian_constants() {
        assert_eq!(DexConstants::ENDIAN_CONSTANT, 0x12345678);
        assert_eq!(DexConstants::REVERSE_ENDIAN_CONSTANT, 0x78563412);
        assert_eq!(DexConstants::K_DEX_ENDIAN_CONSTANT, 0x12345678);
    }

    #[test]
    fn class_definition_order_enforced_version_value() {
        assert_eq!(DexConstants::K_CLASS_DEFINITION_ORDER_ENFORCED_VERSION, 37);
    }

    #[test]
    fn sha1_digest_size_value() {
        assert_eq!(DexConstants::K_SHA1_DIGEST_SIZE, 20);
    }

    #[test]
    fn is_dex_file_true_for_matching_magic() {
        let mut provider = VecProvider::new(b"dex\n035\0");
        assert!(DexConstants::is_dex_file(&mut provider));
    }

    #[test]
    fn is_dex_file_false_for_mismatched_bytes() {
        let mut provider = VecProvider::new(b"notdexfile");
        assert!(!DexConstants::is_dex_file(&mut provider));
    }

    #[test]
    fn is_dex_file_false_when_too_short() {
        let mut provider = VecProvider::new(b"de");
        assert!(!DexConstants::is_dex_file(&mut provider));
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(DexConstants::default(), DexConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = DexConstants;
        assert_eq!(a, a.clone());
    }
}
