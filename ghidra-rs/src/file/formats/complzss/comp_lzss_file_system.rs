//! Port of `ghidra.file.formats.complzss.CompLzssFileSystem`.
//!
//! A pseudo-filesystem holding the decompressed contents of an Apple `complzss` container
//! (an `LzssCompressionHeader` followed by an LZSS stream). The
//! decompression, via [`crate::file::formats::lzss::lzss_codec::decompress`], happens in
//! [`CompLzssFileSystemFactory`](super::comp_lzss_file_system_factory::CompLzssFileSystemFactory);
//! this type only presents the result.

use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::abstract_single_payload_file_system::{
    AbstractSinglePayloadFileSystemBase, SinglePayloadFileSystem,
};
use crate::filesystem::gfilesystem::annotations::file_system_info::FileSystemInfo;
use crate::filesystem::gfilesystem::annotations::file_system_info::PRIORITY_DEFAULT;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::FileAttributes;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;

/// A pseudo-filesystem that contains a single file that represents the decompressed contents
/// of an LZSS-compressed container.
///
/// Mirrors `ghidra.file.formats.complzss.CompLzssFileSystem`; all behaviour comes from the
/// embedded [`AbstractSinglePayloadFileSystemBase`], reachable through `Deref`.
pub struct CompLzssFileSystem {
    base: AbstractSinglePayloadFileSystemBase,
}

impl CompLzssFileSystem {
    /// `@FileSystemInfo(type = "lzss")`.
    pub const FS_TYPE: &'static str = "lzss";
    /// `@FileSystemInfo(description = "LZSS Compression")`.
    pub const DESCRIPTION: &'static str = "LZSS Compression";
    /// `@FileSystemInfo` default priority.
    pub const PRIORITY: i32 = PRIORITY_DEFAULT;

    /// Creates the filesystem over an already-decompressed payload.
    ///
    /// Mirrors `CompLzssFileSystem(FSRLRoot, ByteProvider, String, FileAttributes)`.
    pub fn new(
        fs_fsrl: FsrlRoot,
        payload_provider: Rc<dyn ByteProvider>,
        payload_filename: &str,
        payload_attrs: FileAttributes,
    ) -> Self {
        CompLzssFileSystem {
            base: AbstractSinglePayloadFileSystemBase::new(
                fs_fsrl,
                payload_provider,
                payload_filename,
                payload_attrs,
            ),
        }
    }

    /// The filesystem type string. Mirrors the annotation-derived `getType()`.
    pub fn get_type(&self) -> &'static str {
        Self::FS_TYPE
    }

    /// The filesystem description. Mirrors the annotation-derived `getDescription()`.
    pub fn get_description(&self) -> &'static str {
        Self::DESCRIPTION
    }
}

impl SinglePayloadFileSystem for CompLzssFileSystem {
    const INFO: FileSystemInfo = FileSystemInfo::with(Self::FS_TYPE, Self::DESCRIPTION, Self::PRIORITY);

    fn base(&self) -> &AbstractSinglePayloadFileSystemBase {
        &self.base
    }
}

impl Deref for CompLzssFileSystem {
    type Target = AbstractSinglePayloadFileSystemBase;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for CompLzssFileSystem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::file::formats::lzss::lzss_codec;
    use crate::filesystem::gfilesystem::abstract_single_payload_file_system::test_support::MemProvider;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::filesystem::gfilesystem::g_file::GFile;
    use crate::util::task::DummyMonitor;

    /// Hand-assembled LZSS stream for "ABCABCABCABC", derived from `LzssCodec.decompress`:
    /// flag byte 0x07 (bits LSB-first: literal, literal, literal, back-reference), the three
    /// literals (written to the ring buffer at N-F = 0xFEE..0xFF0), then the pair
    /// `i = 0xEE, j = 0xF6`: position `0xEE | (0xF0 << 4) = 0xFEE`, length `(6 + THRESHOLD) + 1
    /// = 9`, an overlapping copy that repeats "ABC" three more times.
    const COMPRESSED: &[u8] = &[0x07, b'A', b'B', b'C', 0xEE, 0xF6];
    const EXPECTED: &[u8] = b"ABCABCABCABC";

    fn decompress(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        lzss_codec::decompress(&mut out, &mut &src[..]).unwrap();
        out
    }

    /// Builds the filesystem the way `CompLzssFileSystemFactory.create` does: decompress the
    /// stream following the header and name the payload "lzss_decompressed" with no attributes.
    fn mount(compressed: &[u8]) -> CompLzssFileSystem {
        let container = Fsrl::from_string("file:///fw/kernelcache").unwrap();
        let provider = MemProvider::new(decompress(compressed), None);
        CompLzssFileSystem::new(
            container.make_nested(CompLzssFileSystem::FS_TYPE),
            Rc::new(provider),
            "lzss_decompressed",
            FileAttributes::new(),
        )
    }

    #[test]
    fn hand_made_stream_decodes_per_java_algorithm() {
        assert_eq!(decompress(COMPRESSED), EXPECTED);
        // A back-reference into the untouched ring buffer yields the space pre-fill:
        // flags 0x00, pair (0x00, 0xF0) -> position 0xF00, length 3.
        assert_eq!(decompress(&[0x00, 0x00, 0xF0]), b"   ");
    }

    #[test]
    fn annotation_metadata() {
        let fs = mount(COMPRESSED);
        assert_eq!(fs.get_type(), "lzss");
        assert_eq!(fs.get_description(), "LZSS Compression");
        assert_eq!(CompLzssFileSystem::PRIORITY, 0);
        assert_eq!(fs.get_name(), "kernelcache");
    }

    #[test]
    fn listing_and_content_round_trip() {
        let fs = mount(COMPRESSED);
        let listing = fs.get_listing(None).unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].get_name(), "lzss_decompressed");
        assert_eq!(listing[0].get_length(), EXPECTED.len() as i64);
        let monitor = DummyMonitor;
        let bp = fs.get_byte_provider(listing[0], &monitor).unwrap();
        assert_eq!(bp.read_bytes(0, bp.length()).unwrap(), EXPECTED);
        assert!(fs.get_file_attributes(listing[0], &monitor).get_attributes().is_empty());
    }

    #[test]
    fn codec_round_trip_through_filesystem() {
        let original: Vec<u8> = b"lorem ipsum dolor sit amet ".repeat(40);
        let mut compressed = Vec::new();
        lzss_codec::compress(&mut compressed, &mut &original[..]).unwrap();
        assert!(compressed.len() < original.len());
        let fs = mount(&compressed);
        let monitor = DummyMonitor;
        let f = fs.lookup(Some("lzss_decompressed")).unwrap();
        let bp = fs.get_byte_provider(f, &monitor).unwrap();
        assert_eq!(bp.read_bytes(0, bp.length()).unwrap(), original);
    }
}
