//! Port of `ghidra.file.formats.gzip.GZipUtil` (the byte-array and `ByteProvider` checks).
//!
//! The `isGZip(Program)` overload is not ported: it needs `MemoryByteProvider`, which is still
//! unported (see `PORT_MANIFEST.tsv`).

use crate::app::util::bin::byte_provider::ByteProvider;

use super::g_zip_constants::MAGIC_BYTES;

/// Returns `true` if `bytes` starts with the gzip magic bytes. Mirrors `isGZip(byte[])`.
pub fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC_BYTES.len() && bytes[0] == MAGIC_BYTES[0] && bytes[1] == MAGIC_BYTES[1]
}

/// Returns `true` if `provider` starts with the gzip magic bytes; read errors mean `false`.
/// Mirrors `isGZip(ByteProvider)`.
pub fn is_gzip_provider(provider: &dyn ByteProvider) -> bool {
    provider
        .read_bytes(0, MAGIC_BYTES.len() as u64)
        .map(|b| b == MAGIC_BYTES)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;

    #[test]
    fn detects_magic() {
        assert!(is_gzip(&[0x1f, 0x8b, 0x08]));
        assert!(is_gzip(&[0x1f, 0x8b]));
        assert!(!is_gzip(&[0x1f]));
        assert!(!is_gzip(b"PK\x03\x04"));
        assert!(is_gzip_provider(&ByteArrayProvider::new(vec![0x1f, 0x8b, 0])));
        assert!(!is_gzip_provider(&ByteArrayProvider::new(vec![0x1f])));
    }
}
