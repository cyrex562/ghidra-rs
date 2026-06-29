/// Constants for Apple-crushed (iOS-optimized) PNG files.
///
/// Mirrors `ghidra.file.formats.ios.png.CrushedPNGConstants`.

/// Standard PNG signature bytes (8-byte magic).
pub const SIGNATURE_BYTES: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/// The CgBI chunk tag inserted by Apple's PNG crusher.
pub const INSERTED_IOS_CHUNK: [u8; 4] = [0x43, 0x67, 0x42, 0x49];

/// IHDR chunk type tag.
pub const IHDR_CHUNK: [u8; 4] = [0x49, 0x48, 0x44, 0x52];

/// IDAT chunk type tag.
pub const IDAT_CHUNK: [u8; 4] = [0x49, 0x44, 0x41, 0x54];

/// IEND chunk type tag.
pub const IEND_CHUNK: [u8; 4] = [0x49, 0x45, 0x4e, 0x44];

/// Adam7 interlacing: starting row index for each of the 7 passes.
pub const STARTING_ROW: [usize; 7] = [0, 0, 4, 0, 2, 0, 1];

/// Adam7 interlacing: starting column index for each of the 7 passes.
pub const STARTING_COL: [usize; 7] = [0, 4, 0, 2, 0, 1, 0];

/// Adam7 interlacing: row increment for each of the 7 passes.
pub const ROW_INCREMENT: [usize; 7] = [8, 8, 8, 4, 4, 2, 2];

/// Adam7 interlacing: column increment for each of the 7 passes.
pub const COL_INCREMENT: [usize; 7] = [8, 8, 4, 4, 2, 2, 1];

/// Data size of the IHDR chunk in bytes.
pub const IHDR_CHUNK_DATA_SIZE: usize = 13;

/// Total byte size of a generic chunk (length + type + CRC fields, no data).
pub const GENERIC_CHUNK_SIZE: usize = 12;

/// Initial buffer size for repack operations.
pub const INITIAL_REPACK_SIZE: usize = 0x10000;

/// IEND chunk type as a string.
pub const IEND_STRING: &str = "IEND";

/// IHDR chunk type as a string.
pub const IHDR_STRING: &str = "IHDR";

/// Interlace method value for Adam7 interlacing.
pub const ADAM7_INTERLACE: u32 = 1;

/// Interlace method value indicating no interlacing.
pub const INTERLACE_NONE: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_bytes_match_png_spec() {
        assert_eq!(SIGNATURE_BYTES[0], 0x89);
        assert_eq!(&SIGNATURE_BYTES[1..4], b"PNG");
        assert_eq!(SIGNATURE_BYTES.len(), 8);
    }

    #[test]
    fn chunk_tags_match_ascii_names() {
        assert_eq!(&INSERTED_IOS_CHUNK, b"CgBI");
        assert_eq!(&IHDR_CHUNK, b"IHDR");
        assert_eq!(&IDAT_CHUNK, b"IDAT");
        assert_eq!(&IEND_CHUNK, b"IEND");
    }

    #[test]
    fn chunk_string_constants_match_tags() {
        assert_eq!(IEND_STRING.as_bytes(), &IEND_CHUNK);
        assert_eq!(IHDR_STRING.as_bytes(), &IHDR_CHUNK);
    }

    #[test]
    fn adam7_pass_arrays_have_correct_length() {
        assert_eq!(STARTING_ROW.len(), 7);
        assert_eq!(STARTING_COL.len(), 7);
        assert_eq!(ROW_INCREMENT.len(), 7);
        assert_eq!(COL_INCREMENT.len(), 7);
    }

    #[test]
    fn adam7_pass_values_match_java_source() {
        assert_eq!(STARTING_ROW, [0, 0, 4, 0, 2, 0, 1]);
        assert_eq!(STARTING_COL, [0, 4, 0, 2, 0, 1, 0]);
        assert_eq!(ROW_INCREMENT, [8, 8, 8, 4, 4, 2, 2]);
        assert_eq!(COL_INCREMENT, [8, 8, 4, 4, 2, 2, 1]);
    }

    #[test]
    fn size_constants_match_java_source() {
        assert_eq!(IHDR_CHUNK_DATA_SIZE, 13);
        assert_eq!(GENERIC_CHUNK_SIZE, 12);
        assert_eq!(INITIAL_REPACK_SIZE, 0x10000);
    }

    #[test]
    fn interlace_constants_are_distinct() {
        assert_ne!(ADAM7_INTERLACE, INTERLACE_NONE);
        assert_eq!(ADAM7_INTERLACE, 1);
        assert_eq!(INTERLACE_NONE, 0);
    }
}
