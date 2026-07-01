use crate::file::formats::android::art::unknown_art_storage_mode_exception::UnknownArtStorageModeException;

/// Corresponds to Android ART storage modes
/// Reference: https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/image.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ArtStorageMode {
    UncompressedUncompressed = 0,
    LZ4 = 1,
    LZ4HC = 2,
    Count = 3,
}

impl ArtStorageMode {
    pub const DEFAULT: ArtStorageMode = ArtStorageMode::UncompressedUncompressed;
    pub const SIZE: usize = 32;

    pub fn get(value: u32) -> Result<Self, UnknownArtStorageModeException> {
        match value {
            0 => Ok(ArtStorageMode::UncompressedUncompressed),
            1 => Ok(ArtStorageMode::LZ4),
            2 => Ok(ArtStorageMode::LZ4HC),
            3 => Ok(ArtStorageMode::Count),
            _ => Err(UnknownArtStorageModeException::new(value)),
        }
    }

    pub fn ordinal(&self) -> u32 {
        *self as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_uncompressed() {
        let mode = ArtStorageMode::get(0).unwrap();
        assert_eq!(mode, ArtStorageMode::UncompressedUncompressed);
    }

    #[test]
    fn get_lz4() {
        let mode = ArtStorageMode::get(1).unwrap();
        assert_eq!(mode, ArtStorageMode::LZ4);
    }

    #[test]
    fn get_lz4hc() {
        let mode = ArtStorageMode::get(2).unwrap();
        assert_eq!(mode, ArtStorageMode::LZ4HC);
    }

    #[test]
    fn get_count() {
        let mode = ArtStorageMode::get(3).unwrap();
        assert_eq!(mode, ArtStorageMode::Count);
    }

    #[test]
    fn get_invalid() {
        let result = ArtStorageMode::get(4);
        assert!(result.is_err());
    }

    #[test]
    fn get_invalid_large() {
        let result = ArtStorageMode::get(255);
        assert!(result.is_err());
    }

    #[test]
    fn default_is_uncompressed() {
        assert_eq!(ArtStorageMode::DEFAULT, ArtStorageMode::UncompressedUncompressed);
    }

    #[test]
    fn size_constant() {
        assert_eq!(ArtStorageMode::SIZE, 32);
    }

    #[test]
    fn ordinal_values() {
        assert_eq!(ArtStorageMode::UncompressedUncompressed.ordinal(), 0);
        assert_eq!(ArtStorageMode::LZ4.ordinal(), 1);
        assert_eq!(ArtStorageMode::LZ4HC.ordinal(), 2);
        assert_eq!(ArtStorageMode::Count.ordinal(), 3);
    }

    #[test]
    fn clone_and_copy() {
        let mode = ArtStorageMode::LZ4;
        let cloned = mode.clone();
        let copied = mode;
        assert_eq!(cloned, copied);
    }

    #[test]
    fn ordering() {
        assert!(ArtStorageMode::UncompressedUncompressed < ArtStorageMode::LZ4);
        assert!(ArtStorageMode::LZ4 < ArtStorageMode::LZ4HC);
        assert!(ArtStorageMode::LZ4HC < ArtStorageMode::Count);
    }
}
