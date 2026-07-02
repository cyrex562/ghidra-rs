use crate::file::formats::android::art::art_storage_mode::ArtStorageMode;
use crate::file::formats::android::art::unknown_art_storage_mode_exception::UnknownArtStorageModeException;

/// Storage method and size information for ART (Android Runtime) image data.
///
/// The image may be compressed or uncompressed. For compressed images, the compressed size
/// in the file differs from the decompressed size in memory.
pub trait ArtCompression {
    /// Storage method for the image.
    ///
    /// The image may be compressed.
    ///
    /// # Returns
    ///
    /// The storage method, or an error if an unknown storage mode is encountered.
    ///
    /// # Errors
    ///
    /// Returns `UnknownArtStorageModeException` when an unknown storage mode is encountered.
    fn get_storage_mode(&self) -> Result<ArtStorageMode, UnknownArtStorageModeException>;

    /// Data size for the image data excluding the bitmap and header.
    ///
    /// For compressed images, this is the compressed size in the file.
    ///
    /// # Returns
    ///
    /// The compressed size in bytes.
    fn get_compressed_size(&self) -> i32;

    /// Offset to the start of the compressed bytes.
    ///
    /// Also, offset of where to place the decompressed bytes.
    ///
    /// # Returns
    ///
    /// The offset to the compressed bytes.
    fn get_compressed_offset(&self) -> i64;

    /// Expected size of the decompressed bytes.
    ///
    /// # Returns
    ///
    /// The expected decompressed size in bytes.
    fn get_decompressed_size(&self) -> i32;

    /// Offset to the start of the decompressed bytes.
    ///
    /// # Returns
    ///
    /// The offset to the decompressed bytes.
    fn get_decompressed_offset(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockArtCompression {
        storage_mode: ArtStorageMode,
        compressed_size: i32,
        compressed_offset: i64,
        decompressed_size: i32,
        decompressed_offset: i64,
    }

    impl ArtCompression for MockArtCompression {
        fn get_storage_mode(&self) -> Result<ArtStorageMode, UnknownArtStorageModeException> {
            Ok(self.storage_mode)
        }

        fn get_compressed_size(&self) -> i32 {
            self.compressed_size
        }

        fn get_compressed_offset(&self) -> i64 {
            self.compressed_offset
        }

        fn get_decompressed_size(&self) -> i32 {
            self.decompressed_size
        }

        fn get_decompressed_offset(&self) -> i64 {
            self.decompressed_offset
        }
    }

    #[test]
    fn trait_object_construction() {
        let mock = MockArtCompression {
            storage_mode: ArtStorageMode::UncompressedUncompressed,
            compressed_size: 1024,
            compressed_offset: 512,
            decompressed_size: 2048,
            decompressed_offset: 1024,
        };
        let _: &dyn ArtCompression = &mock;
    }

    #[test]
    fn uncompressed_storage_mode() {
        let mock = MockArtCompression {
            storage_mode: ArtStorageMode::UncompressedUncompressed,
            compressed_size: 1024,
            compressed_offset: 0,
            decompressed_size: 1024,
            decompressed_offset: 0,
        };

        assert_eq!(
            mock.get_storage_mode().unwrap(),
            ArtStorageMode::UncompressedUncompressed
        );
        assert_eq!(mock.get_compressed_size(), 1024);
        assert_eq!(mock.get_compressed_offset(), 0);
        assert_eq!(mock.get_decompressed_size(), 1024);
        assert_eq!(mock.get_decompressed_offset(), 0);
    }

    #[test]
    fn lz4_storage_mode() {
        let mock = MockArtCompression {
            storage_mode: ArtStorageMode::LZ4,
            compressed_size: 512,
            compressed_offset: 256,
            decompressed_size: 2048,
            decompressed_offset: 512,
        };

        assert_eq!(mock.get_storage_mode().unwrap(), ArtStorageMode::LZ4);
        assert_eq!(mock.get_compressed_size(), 512);
        assert_eq!(mock.get_compressed_offset(), 256);
        assert_eq!(mock.get_decompressed_size(), 2048);
        assert_eq!(mock.get_decompressed_offset(), 512);
    }

    #[test]
    fn lz4hc_storage_mode() {
        let mock = MockArtCompression {
            storage_mode: ArtStorageMode::LZ4HC,
            compressed_size: 384,
            compressed_offset: 128,
            decompressed_size: 4096,
            decompressed_offset: 256,
        };

        assert_eq!(mock.get_storage_mode().unwrap(), ArtStorageMode::LZ4HC);
        assert_eq!(mock.get_compressed_size(), 384);
        assert_eq!(mock.get_compressed_offset(), 128);
        assert_eq!(mock.get_decompressed_size(), 4096);
        assert_eq!(mock.get_decompressed_offset(), 256);
    }

    #[test]
    fn large_offsets_and_sizes() {
        let mock = MockArtCompression {
            storage_mode: ArtStorageMode::LZ4,
            compressed_size: i32::MAX,
            compressed_offset: i64::MAX,
            decompressed_size: i32::MAX - 1,
            decompressed_offset: i64::MAX - 1,
        };

        assert_eq!(mock.get_compressed_size(), i32::MAX);
        assert_eq!(mock.get_compressed_offset(), i64::MAX);
        assert_eq!(mock.get_decompressed_size(), i32::MAX - 1);
        assert_eq!(mock.get_decompressed_offset(), i64::MAX - 1);
    }

    #[test]
    fn zero_values() {
        let mock = MockArtCompression {
            storage_mode: ArtStorageMode::UncompressedUncompressed,
            compressed_size: 0,
            compressed_offset: 0,
            decompressed_size: 0,
            decompressed_offset: 0,
        };

        assert_eq!(mock.get_compressed_size(), 0);
        assert_eq!(mock.get_compressed_offset(), 0);
        assert_eq!(mock.get_decompressed_size(), 0);
        assert_eq!(mock.get_decompressed_offset(), 0);
    }

    #[test]
    fn different_offset_scenarios() {
        let mock1 = MockArtCompression {
            storage_mode: ArtStorageMode::UncompressedUncompressed,
            compressed_size: 1000,
            compressed_offset: 100,
            decompressed_size: 1000,
            decompressed_offset: 200,
        };

        assert_eq!(mock1.get_compressed_offset(), 100);
        assert_eq!(mock1.get_decompressed_offset(), 200);

        let mock2 = MockArtCompression {
            storage_mode: ArtStorageMode::LZ4,
            compressed_size: 500,
            compressed_offset: 2000,
            decompressed_size: 1500,
            decompressed_offset: 2100,
        };

        assert_eq!(mock2.get_compressed_offset(), 2000);
        assert_eq!(mock2.get_decompressed_offset(), 2100);
    }
}
