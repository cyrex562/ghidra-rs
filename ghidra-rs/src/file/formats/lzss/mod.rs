pub mod lzss_codec;
pub mod lzss_constants;

pub use lzss_codec::{compress, decompress, F, N, NIL, THRESHOLD};
pub use lzss_constants::{
    HEADER_LENGTH, PADDING_LENGTH, SIGNATURE_COMPRESSION, SIGNATURE_COMPRESSION_BYTES,
    SIGNATURE_LZSS, SIGNATURE_LZSS_BYTES,
};
