use crate::app::util::bin::binary_reader::BinaryReader;

/// Android Profiling (.PROF) files.
///
/// "current profiles are stored next to the dex files under the oat folder"
///
/// Reference:
/// - <https://android.googlesource.com/platform/art/+/refs/heads/android11-release/libprofile/profile/profile_compilation_info.cc>
/// - <https://android.googlesource.com/platform/frameworks/native/+/master/cmds/installd/utils.cpp>
/// - <https://android.googlesource.com/platform/frameworks/native/+/master/cmds/installd/dexopt.cpp>
///
/// Mirrors `ghidra.file.formats.android.prof.ProfileConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProfileConstants;

impl ProfileConstants {
    pub const K_PROFILE_MAGIC: &'static [u8] = b"pro\0";
    pub const K_PROFILE_MAGIC_LENGTH: usize = 4;

    pub const K_PROFILE_VERSION_008: &'static [u8] = b"008\0";
    pub const K_PROFILE_VERSION_009: &'static [u8] = b"009\0";
    /// Android 10, Android 11
    pub const K_PROFILE_VERSION_010: &'static [u8] = b"010\0";

    pub const K_PROFILE_VERSION_FOR_BOOT_IMAGE_012: &'static [u8] = b"012\0";

    pub const K_DEX_METADATA_PROFILE_ENTRY: &'static str = "primary.prof";

    pub const K_PROFILE_VERSION_WITH_COUNTERS: &'static [u8] = b"500\0";

    /// Converts the byte array into String and trims it.
    pub fn to_string(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).trim().to_string()
    }

    /// Checks if the reader contains a profile file signature.
    /// Returns true if the reader starts with the profile magic and version 010.
    pub fn is_profile(reader: &dyn BinaryReader) -> bool {
        if let Ok(magic_bytes) = reader.read_byte_array(0, Self::K_PROFILE_MAGIC_LENGTH) {
            if magic_bytes == Self::K_PROFILE_MAGIC {
                if let Ok(version_bytes) = reader.read_byte_array(
                    Self::K_PROFILE_MAGIC_LENGTH as u64,
                    Self::K_PROFILE_VERSION_010.len(),
                ) {
                    if version_bytes == Self::K_PROFILE_VERSION_010 {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::byte_provider_input_stream::ByteProviderInputStream;
    use crate::app::util::bin::binary_reader::BinaryReaderImpl;
    use crate::app::util::bin::input_stream_byte_provider::InputStreamByteProvider;

    #[test]
    fn magic_value() {
        assert_eq!(ProfileConstants::K_PROFILE_MAGIC, b"pro\0");
    }

    #[test]
    fn magic_length() {
        assert_eq!(ProfileConstants::K_PROFILE_MAGIC_LENGTH, 4);
    }

    #[test]
    fn magic_length_matches_constant() {
        assert_eq!(
            ProfileConstants::K_PROFILE_MAGIC.len(),
            ProfileConstants::K_PROFILE_MAGIC_LENGTH
        );
    }

    #[test]
    fn version_008_value() {
        assert_eq!(ProfileConstants::K_PROFILE_VERSION_008, b"008\0");
    }

    #[test]
    fn version_009_value() {
        assert_eq!(ProfileConstants::K_PROFILE_VERSION_009, b"009\0");
    }

    #[test]
    fn version_010_value() {
        assert_eq!(ProfileConstants::K_PROFILE_VERSION_010, b"010\0");
    }

    #[test]
    fn version_for_boot_image_012_value() {
        assert_eq!(
            ProfileConstants::K_PROFILE_VERSION_FOR_BOOT_IMAGE_012,
            b"012\0"
        );
    }

    #[test]
    fn dex_metadata_profile_entry() {
        assert_eq!(
            ProfileConstants::K_DEX_METADATA_PROFILE_ENTRY,
            "primary.prof"
        );
    }

    #[test]
    fn version_with_counters_value() {
        assert_eq!(ProfileConstants::K_PROFILE_VERSION_WITH_COUNTERS, b"500\0");
    }

    #[test]
    fn to_string_with_null_terminator() {
        let bytes = b"test\0";
        assert_eq!(ProfileConstants::to_string(bytes), "test");
    }

    #[test]
    fn to_string_with_whitespace() {
        let bytes = b"  test  \0";
        assert_eq!(ProfileConstants::to_string(bytes), "test");
    }

    #[test]
    fn to_string_with_only_whitespace() {
        let bytes = b"   \0";
        assert_eq!(ProfileConstants::to_string(bytes), "");
    }

    #[test]
    fn all_versions_are_same_length() {
        assert_eq!(
            ProfileConstants::K_PROFILE_VERSION_008.len(),
            ProfileConstants::K_PROFILE_VERSION_009.len()
        );
        assert_eq!(
            ProfileConstants::K_PROFILE_VERSION_009.len(),
            ProfileConstants::K_PROFILE_VERSION_010.len()
        );
        assert_eq!(
            ProfileConstants::K_PROFILE_VERSION_010.len(),
            ProfileConstants::K_PROFILE_VERSION_FOR_BOOT_IMAGE_012.len()
        );
    }

    #[test]
    fn is_profile_with_matching_magic_and_version() {
        let data = b"pro\0010\0extra data".to_vec();
        let provider = InputStreamByteProvider::new(std::io::Cursor::new(data));
        let mut stream = ByteProviderInputStream::new(provider, 0);
        let reader = BinaryReaderImpl::new(&mut stream, crate::app::util::bin::binary_reader::Endian::Little);

        assert!(ProfileConstants::is_profile(&reader));
    }

    #[test]
    fn is_profile_with_wrong_magic() {
        let data = b"DEX\0010\0extra data".to_vec();
        let provider = InputStreamByteProvider::new(std::io::Cursor::new(data));
        let mut stream = ByteProviderInputStream::new(provider, 0);
        let reader = BinaryReaderImpl::new(&mut stream, crate::app::util::bin::binary_reader::Endian::Little);

        assert!(!ProfileConstants::is_profile(&reader));
    }

    #[test]
    fn is_profile_with_wrong_version() {
        let data = b"pro\0008\0extra data".to_vec();
        let provider = InputStreamByteProvider::new(std::io::Cursor::new(data));
        let mut stream = ByteProviderInputStream::new(provider, 0);
        let reader = BinaryReaderImpl::new(&mut stream, crate::app::util::bin::binary_reader::Endian::Little);

        assert!(!ProfileConstants::is_profile(&reader));
    }

    #[test]
    fn is_profile_with_short_data() {
        let data = b"pro".to_vec();
        let provider = InputStreamByteProvider::new(std::io::Cursor::new(data));
        let mut stream = ByteProviderInputStream::new(provider, 0);
        let reader = BinaryReaderImpl::new(&mut stream, crate::app::util::bin::binary_reader::Endian::Little);

        assert!(!ProfileConstants::is_profile(&reader));
    }

    #[test]
    fn is_profile_with_empty_data() {
        let data = Vec::new();
        let provider = InputStreamByteProvider::new(std::io::Cursor::new(data));
        let mut stream = ByteProviderInputStream::new(provider, 0);
        let reader = BinaryReaderImpl::new(&mut stream, crate::app::util::bin::binary_reader::Endian::Little);

        assert!(!ProfileConstants::is_profile(&reader));
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(ProfileConstants::default(), ProfileConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = ProfileConstants;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn versions_are_distinct() {
        assert_ne!(
            ProfileConstants::K_PROFILE_VERSION_008,
            ProfileConstants::K_PROFILE_VERSION_009
        );
        assert_ne!(
            ProfileConstants::K_PROFILE_VERSION_009,
            ProfileConstants::K_PROFILE_VERSION_010
        );
        assert_ne!(
            ProfileConstants::K_PROFILE_VERSION_008,
            ProfileConstants::K_PROFILE_VERSION_010
        );
        assert_ne!(
            ProfileConstants::K_PROFILE_VERSION_010,
            ProfileConstants::K_PROFILE_VERSION_FOR_BOOT_IMAGE_012
        );
    }
}
