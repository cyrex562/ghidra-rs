/// FBPK (Facebook Package) constants and utilities.
///
/// Port of `ghidra.file.formats.android.fbpk.FBPK_Constants`.

use crate::program::model::listing::Program;

/// Version 1
pub const VERSION_1: i32 = 1;
/// Version 2
pub const VERSION_2: i32 = 2;

/// FBPK magic string
pub const FBPK: &str = "FBPK";
/// FBPT magic string
pub const FBPT: &str = "FBPT";
/// UFPK magic string
pub const UFPK: &str = "UFPK";
/// UFSM magic string
pub const UFSM: &str = "UFSM";
/// UFSP magic string
pub const UFSP: &str = "UFSP";

/// FBPK magic value
pub const FBPK_MAGIC: i32 = 0x4B504246;
/// FBPT magic value
pub const FBPT_MAGIC: i32 = 0x54504246;
/// UFPK magic value
pub const UFPK_MAGIC: i32 = 0x4B504655;
/// UFSM magic value
pub const UFSM_MAGIC: i32 = 0x4D534655;
/// UFSP magic value
pub const UFSP_MAGIC: i32 = 0x50534655;

/// Maximum length for name
pub const NAME_MAX_LENGTH: i32 = 36;
/// Partition type: directory
pub const PARTITION_TYPE_DIRECTORY: i32 = 0;
/// Partition type: file
pub const PARTITION_TYPE_FILE: i32 = 1;

/// Partition table label
pub const PARTITION_TABLE: &str = "partition table";
/// V1 last partition entry label
pub const V1_LAST_PARTITION_ENTRY: &str = "last_parti";

/// V1 version maximum length
pub const V1_VERSION_MAX_LENGTH: i32 = 68;
/// V1 padding length
pub const V1_PADDING_LENGTH: i32 = 2;

/// V2 partition prefix
pub const V2_PARTITION: &str = "partition:";
/// V2 UFS label
pub const V2_UFS: &str = "ufs";
/// V2 UFS firmware update label
pub const V2_UFSFWUPDATE: &str = "ufsfwupdate";

/// V2 partition name maximum length
pub const V2_PARTITION_NAME_MAX_LENGTH: i32 = 76;
/// V2 string 1 maximum length
pub const V2_STRING1_MAX_LENGTH: i32 = 16;
/// V2 string 2 maximum length
pub const V2_STRING2_MAX_LENGTH: i32 = 68;
/// V2 format maximum length
pub const V2_FORMAT_MAX_LENGTH: i32 = 14;
/// V2 GUID maximum length
pub const V2_GUID_MAX_LENGTH: i32 = 44;
/// V2 UFPK string 1 maximum length
pub const V2_UFPK_STRING1_MAX_LENGTH: i32 = 76;

/// Check if the given program is an FBPK binary by reading the magic value at the minimum address.
pub fn is_fbpk(program: &dyn Program) -> bool {
    if let Some(memory) = program.get_memory() {
        if let Some(min_addr) = program.get_image_base() {
            let mut buf = [0u8; 4];
            let bytes_read = memory.get_bytes(&min_addr, &mut buf);
            if bytes_read == 4 {
                let magic = if memory.is_big_endian() {
                    i32::from_be_bytes(buf)
                } else {
                    i32::from_le_bytes(buf)
                };
                return magic == FBPK_MAGIC;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constants() {
        assert_eq!(VERSION_1, 1);
        assert_eq!(VERSION_2, 2);
    }

    #[test]
    fn test_magic_strings() {
        assert_eq!(FBPK, "FBPK");
        assert_eq!(FBPT, "FBPT");
        assert_eq!(UFPK, "UFPK");
        assert_eq!(UFSM, "UFSM");
        assert_eq!(UFSP, "UFSP");
    }

    #[test]
    fn test_magic_values() {
        assert_eq!(FBPK_MAGIC, 0x4B504246);
        assert_eq!(FBPT_MAGIC, 0x54504246);
        assert_eq!(UFPK_MAGIC, 0x4B504655);
        assert_eq!(UFSM_MAGIC, 0x4D534655);
        assert_eq!(UFSP_MAGIC, 0x50534655);
    }

    #[test]
    fn test_partition_constants() {
        assert_eq!(NAME_MAX_LENGTH, 36);
        assert_eq!(PARTITION_TYPE_DIRECTORY, 0);
        assert_eq!(PARTITION_TYPE_FILE, 1);
    }

    #[test]
    fn test_partition_table_labels() {
        assert_eq!(PARTITION_TABLE, "partition table");
        assert_eq!(V1_LAST_PARTITION_ENTRY, "last_parti");
    }

    #[test]
    fn test_v1_constants() {
        assert_eq!(V1_VERSION_MAX_LENGTH, 68);
        assert_eq!(V1_PADDING_LENGTH, 2);
    }

    #[test]
    fn test_v2_labels() {
        assert_eq!(V2_PARTITION, "partition:");
        assert_eq!(V2_UFS, "ufs");
        assert_eq!(V2_UFSFWUPDATE, "ufsfwupdate");
    }

    #[test]
    fn test_v2_length_constants() {
        assert_eq!(V2_PARTITION_NAME_MAX_LENGTH, 76);
        assert_eq!(V2_STRING1_MAX_LENGTH, 16);
        assert_eq!(V2_STRING2_MAX_LENGTH, 68);
        assert_eq!(V2_FORMAT_MAX_LENGTH, 14);
        assert_eq!(V2_GUID_MAX_LENGTH, 44);
        assert_eq!(V2_UFPK_STRING1_MAX_LENGTH, 76);
    }
}
