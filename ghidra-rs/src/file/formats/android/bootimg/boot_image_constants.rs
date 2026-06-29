/// Android boot image constants.
///
/// See <https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/master/include/bootimg/bootimg.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BootImageConstants;

impl BootImageConstants {
    pub const BOOT_MAGIC: &'static str = "ANDROID!";
    pub const BOOT_MAGIC_SIZE: u32 = 8;
    pub const BOOT_NAME_SIZE: u32 = 16;
    pub const BOOT_ARGS_SIZE: u32 = 512;
    pub const BOOT_EXTRA_ARGS_SIZE: u32 = 1024;

    pub const ID_SIZE: u32 = 8;

    pub const V3_HEADER_SIZE: u32 = 4096;
    pub const V3_PAGE_SIZE: u32 = 4096;
    pub const V4_HEADER_SIZE: u32 = Self::V3_HEADER_SIZE;
    pub const V4_PAGE_SIZE: u32 = Self::V3_PAGE_SIZE;

    pub const VENDOR_BOOT_MAGIC: &'static str = "VNDRBOOT";
    pub const VENDOR_BOOT_MAGIC_SIZE: u32 = 8;
    pub const VENDOR_BOOT_ARGS_SIZE: u32 = 2048;
    pub const VENDOR_BOOT_NAME_SIZE: u32 = 16;

    pub const VENDOR_RAMDISK_TYPE_NONE: u32 = 0;
    pub const VENDOR_RAMDISK_TYPE_PLATFORM: u32 = 1;
    pub const VENDOR_RAMDISK_TYPE_RECOVERY: u32 = 2;
    pub const VENDOR_RAMDISK_TYPE_DLKM: u32 = 3;
    pub const VENDOR_RAMDISK_NAME_SIZE: u32 = 32;
    pub const VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: u32 = 16;

    pub const SECOND_STAGE: &'static str = "second stage";
    pub const RAMDISK: &'static str = "ramdisk";
    pub const KERNEL: &'static str = "kernel";
    pub const DTB: &'static str = "dtb";

    pub const HEADER_VERSION_OFFSET: u32 = 0x28;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_magic_value() {
        assert_eq!(BootImageConstants::BOOT_MAGIC, "ANDROID!");
    }

    #[test]
    fn boot_magic_size_matches_string_length() {
        assert_eq!(
            BootImageConstants::BOOT_MAGIC_SIZE as usize,
            BootImageConstants::BOOT_MAGIC.len()
        );
    }

    #[test]
    fn vendor_boot_magic_value() {
        assert_eq!(BootImageConstants::VENDOR_BOOT_MAGIC, "VNDRBOOT");
    }

    #[test]
    fn vendor_boot_magic_size_matches_string_length() {
        assert_eq!(
            BootImageConstants::VENDOR_BOOT_MAGIC_SIZE as usize,
            BootImageConstants::VENDOR_BOOT_MAGIC.len()
        );
    }

    #[test]
    fn v4_sizes_alias_v3() {
        assert_eq!(
            BootImageConstants::V4_HEADER_SIZE,
            BootImageConstants::V3_HEADER_SIZE
        );
        assert_eq!(
            BootImageConstants::V4_PAGE_SIZE,
            BootImageConstants::V3_PAGE_SIZE
        );
    }

    #[test]
    fn ramdisk_type_sequential() {
        assert_eq!(BootImageConstants::VENDOR_RAMDISK_TYPE_NONE, 0);
        assert_eq!(BootImageConstants::VENDOR_RAMDISK_TYPE_PLATFORM, 1);
        assert_eq!(BootImageConstants::VENDOR_RAMDISK_TYPE_RECOVERY, 2);
        assert_eq!(BootImageConstants::VENDOR_RAMDISK_TYPE_DLKM, 3);
    }

    #[test]
    fn header_version_offset_value() {
        assert_eq!(BootImageConstants::HEADER_VERSION_OFFSET, 0x28);
    }

    #[test]
    fn section_name_strings() {
        assert_eq!(BootImageConstants::SECOND_STAGE, "second stage");
        assert_eq!(BootImageConstants::RAMDISK, "ramdisk");
        assert_eq!(BootImageConstants::KERNEL, "kernel");
        assert_eq!(BootImageConstants::DTB, "dtb");
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(BootImageConstants::default(), BootImageConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = BootImageConstants;
        assert_eq!(a, a.clone());
    }
}
