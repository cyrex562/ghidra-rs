/// Android OTA update payload constants.
///
/// See <https://android.googlesource.com/platform/system/update_engine/+/refs/heads/android10-release/payload_consumer/payload_constants.cc>
/// and <https://android.googlesource.com/platform/system/update_engine/+/refs/heads/android10-release/payload_generator/payload_file.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PayloadConstants;

impl PayloadConstants {
    pub const K_CHROME_OS_MAJOR_PAYLOAD_VERSION: u64 = 1;
    pub const K_BRILLO_MAJOR_PAYLOAD_VERSION: u64 = 2;

    pub const K_MIN_SUPPORTED_MINOR_PAYLOAD_VERSION: u32 = 1;
    pub const K_MAX_SUPPORTED_MINOR_PAYLOAD_VERSION: u32 = 6;

    pub const K_FULL_PAYLOAD_MINOR_VERSION: u32 = 0;
    pub const K_IN_PLACE_MINOR_PAYLOAD_VERSION: u32 = 1;
    pub const K_SOURCE_MINOR_PAYLOAD_VERSION: u32 = 2;
    pub const K_OP_SRC_HASH_MINOR_PAYLOAD_VERSION: u32 = 3;
    pub const K_BROTLI_BSDIFF_MINOR_PAYLOAD_VERSION: u32 = 4;
    pub const K_PUFFDIFF_MINOR_PAYLOAD_VERSION: u32 = 5;
    pub const K_VERITY_MINOR_PAYLOAD_VERSION: u32 = 6;

    pub const K_MIN_SUPPORTED_MAJOR_PAYLOAD_VERSION: u64 = 1;
    pub const K_MAX_SUPPORTED_MAJOR_PAYLOAD_VERSION: u64 = 2;

    pub const K_MAX_PAYLOAD_HEADER_SIZE: u64 = 24;

    pub const K_PARTITION_NAME_KERNEL: &'static str = "kernel";
    pub const K_PARTITION_NAME_ROOT: &'static str = "root";

    pub const K_DELTA_MAGIC: &'static str = "CrAU";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn major_version_range() {
        assert_eq!(PayloadConstants::K_CHROME_OS_MAJOR_PAYLOAD_VERSION, 1);
        assert_eq!(PayloadConstants::K_BRILLO_MAJOR_PAYLOAD_VERSION, 2);
        assert_eq!(PayloadConstants::K_MIN_SUPPORTED_MAJOR_PAYLOAD_VERSION, 1);
        assert_eq!(PayloadConstants::K_MAX_SUPPORTED_MAJOR_PAYLOAD_VERSION, 2);
    }

    #[test]
    fn minor_version_range() {
        assert_eq!(PayloadConstants::K_MIN_SUPPORTED_MINOR_PAYLOAD_VERSION, 1);
        assert_eq!(PayloadConstants::K_MAX_SUPPORTED_MINOR_PAYLOAD_VERSION, 6);
        assert!(
            PayloadConstants::K_MIN_SUPPORTED_MINOR_PAYLOAD_VERSION
                <= PayloadConstants::K_MAX_SUPPORTED_MINOR_PAYLOAD_VERSION
        );
    }

    #[test]
    fn minor_versions_sequential() {
        assert_eq!(PayloadConstants::K_FULL_PAYLOAD_MINOR_VERSION, 0);
        assert_eq!(PayloadConstants::K_IN_PLACE_MINOR_PAYLOAD_VERSION, 1);
        assert_eq!(PayloadConstants::K_SOURCE_MINOR_PAYLOAD_VERSION, 2);
        assert_eq!(PayloadConstants::K_OP_SRC_HASH_MINOR_PAYLOAD_VERSION, 3);
        assert_eq!(PayloadConstants::K_BROTLI_BSDIFF_MINOR_PAYLOAD_VERSION, 4);
        assert_eq!(PayloadConstants::K_PUFFDIFF_MINOR_PAYLOAD_VERSION, 5);
        assert_eq!(PayloadConstants::K_VERITY_MINOR_PAYLOAD_VERSION, 6);
    }

    #[test]
    fn max_payload_header_size() {
        assert_eq!(PayloadConstants::K_MAX_PAYLOAD_HEADER_SIZE, 24);
    }

    #[test]
    fn partition_names() {
        assert_eq!(PayloadConstants::K_PARTITION_NAME_KERNEL, "kernel");
        assert_eq!(PayloadConstants::K_PARTITION_NAME_ROOT, "root");
    }

    #[test]
    fn delta_magic_value() {
        assert_eq!(PayloadConstants::K_DELTA_MAGIC, "CrAU");
        assert_eq!(PayloadConstants::K_DELTA_MAGIC.len(), 4);
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(PayloadConstants::default(), PayloadConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = PayloadConstants;
        assert_eq!(a, a.clone());
    }
}
