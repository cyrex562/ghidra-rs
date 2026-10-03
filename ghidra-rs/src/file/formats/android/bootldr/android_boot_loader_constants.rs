use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

/// Android boot loader constants and utilities.
///
/// Source: <https://android.googlesource.com/device/lge/mako/+/android-4.2.2_r1/releasetools.py>
///
/// Mirrors `ghidra.file.formats.android.bootldr.AndroidBootLoaderConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AndroidBootLoaderConstants;

impl AndroidBootLoaderConstants {
    pub const BOOTLDR_NAME: &'static str = "bootloader_images_header";
    pub const BOOTLDR_MAGIC: &'static str = "BOOTLDR!";
    pub const BOOTLDR_MAGIC_SIZE: usize = Self::BOOTLDR_MAGIC.len();
    pub const IMG_INFO_NAME: &'static str = "img_info";
    pub const IMG_INFO_NAME_LENGTH: usize = 64;

    /// Returns true if the given program contains the bootloader magic bytes.
    pub fn is_boot_loader(program: &ProgramDB) -> bool {
        let factory = match program.get_address_factory() {
            Some(f) => f,
            None => return false,
        };

        let default_space = match factory.get_default_address_space() {
            Some(s) => s,
            None => return false,
        };

        let min_address = default_space.min_address();

        let memory_read_result = {
            let memory = program.get_memory();
            memory.read().ok().map(|memory_guard| {
                let mut bytes = vec![0u8; Self::BOOTLDR_MAGIC_SIZE];
                let bytes_read = memory_guard.get_bytes(&min_address, &mut bytes);
                (bytes_read, bytes)
            })
        };

        if let Some((bytes_read, bytes)) = memory_read_result {
            if bytes_read == Self::BOOTLDR_MAGIC_SIZE {
                if let Ok(magic_str) = std::str::from_utf8(&bytes) {
                    return magic_str.trim() == Self::BOOTLDR_MAGIC;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootldr_name_value() {
        assert_eq!(
            AndroidBootLoaderConstants::BOOTLDR_NAME,
            "bootloader_images_header"
        );
    }

    #[test]
    fn bootldr_magic_value() {
        assert_eq!(AndroidBootLoaderConstants::BOOTLDR_MAGIC, "BOOTLDR!");
    }

    #[test]
    fn bootldr_magic_size_matches_string_length() {
        assert_eq!(
            AndroidBootLoaderConstants::BOOTLDR_MAGIC_SIZE,
            AndroidBootLoaderConstants::BOOTLDR_MAGIC.len()
        );
    }

    #[test]
    fn img_info_name_value() {
        assert_eq!(AndroidBootLoaderConstants::IMG_INFO_NAME, "img_info");
    }

    #[test]
    fn img_info_name_length_value() {
        assert_eq!(AndroidBootLoaderConstants::IMG_INFO_NAME_LENGTH, 64);
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(
            AndroidBootLoaderConstants::default(),
            AndroidBootLoaderConstants
        );
    }

    #[test]
    fn clone_is_equal() {
        let a = AndroidBootLoaderConstants;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn constants_are_distinct() {
        assert_ne!(
            AndroidBootLoaderConstants::BOOTLDR_NAME,
            AndroidBootLoaderConstants::IMG_INFO_NAME
        );
        assert_ne!(
            AndroidBootLoaderConstants::BOOTLDR_MAGIC_SIZE,
            AndroidBootLoaderConstants::IMG_INFO_NAME_LENGTH
        );
    }
}
