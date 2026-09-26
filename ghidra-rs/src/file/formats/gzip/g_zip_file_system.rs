//! Port of `ghidra.file.formats.gzip.GZipFileSystem`.
//!
//! A pseudo-filesystem that contains a single file: the decompressed contents of a gzip
//! container. The decompression and header-attribute extraction happen in
//! `GZipFileSystemFactory` (not yet ported); this type only presents the result.

use std::ops::{Deref, DerefMut};
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::abstract_single_payload_file_system::{
    AbstractSinglePayloadFileSystemBase, SinglePayloadFileSystem,
};
use crate::filesystem::gfilesystem::annotations::file_system_info::FileSystemInfo;
use crate::filesystem::gfilesystem::annotations::file_system_info::PRIORITY_LOW;
use crate::filesystem::gfilesystem::fileinfo::file_attributes::FileAttributes;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;

/// A pseudo-filesystem that contains a single file that represents the decompressed contents
/// of the gzip file.
///
/// If the gzip header records the original filename, that is used as the payload's name.
///
/// Mirrors `ghidra.file.formats.gzip.GZipFileSystem`; all behaviour comes from the embedded
/// [`AbstractSinglePayloadFileSystemBase`], reachable through `Deref`.
pub struct GZipFileSystem {
    base: AbstractSinglePayloadFileSystemBase,
}

impl GZipFileSystem {
    /// `@FileSystemInfo(type = "gzip")`.
    pub const FS_TYPE: &'static str = "gzip";
    /// `@FileSystemInfo(description = "GZIP")`.
    pub const DESCRIPTION: &'static str = "GZIP";
    /// `@FileSystemInfo(priority = FileSystemInfo.PRIORITY_LOW)`.
    pub const PRIORITY: i32 = PRIORITY_LOW;

    /// Creates the filesystem over an already-decompressed payload.
    ///
    /// Mirrors `GZipFileSystem(FSRLRoot, ByteProvider, String, FileAttributes)`.
    pub fn new(
        fs_fsrl: FsrlRoot,
        payload_provider: Rc<dyn ByteProvider>,
        payload_filename: &str,
        payload_attrs: FileAttributes,
    ) -> Self {
        GZipFileSystem {
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

impl SinglePayloadFileSystem for GZipFileSystem {
    const INFO: FileSystemInfo = FileSystemInfo::with(Self::FS_TYPE, Self::DESCRIPTION, Self::PRIORITY);

    fn base(&self) -> &AbstractSinglePayloadFileSystemBase {
        &self.base
    }
}

impl Deref for GZipFileSystem {
    type Target = AbstractSinglePayloadFileSystemBase;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for GZipFileSystem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    use flate2::read::GzDecoder;
    use flate2::{Compression, GzBuilder};

    use crate::filesystem::gfilesystem::abstract_single_payload_file_system::test_support::MemProvider;
    use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
    use crate::filesystem::gfilesystem::fileinfo::file_attributes::FileAttributeValue;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::filesystem::gfilesystem::g_file::GFile;
    use crate::util::task::DummyMonitor;

    const PAYLOAD: &[u8] = b"The quick brown fox jumps over the lazy dog.\n0123456789\n";

    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut enc = GzBuilder::new()
            .filename("fox.txt")
            .comment("a comment")
            .mtime(1_700_000_000)
            .write(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    /// Builds the filesystem the way `GZipFileSystemFactory.create` does: decompress the
    /// container, name the payload from the gzip header, and record the header attributes
    /// plus the decompressed size.
    fn mount(container_bytes: &[u8]) -> GZipFileSystem {
        let container_fsrl = Fsrl::from_string("file:///tmp/fox.txt.gz").unwrap();
        let mut dec = GzDecoder::new(container_bytes);
        let mut payload = Vec::new();
        dec.read_to_end(&mut payload).unwrap();
        let header = dec.header().unwrap();
        let name = String::from_utf8(header.filename().unwrap().to_vec()).unwrap();
        let comment = header.comment().map(|c| String::from_utf8_lossy(c).into_owned());
        let mtime = header.mtime() as i64;

        let mut attrs = FileAttributes::of([
            (FileAttributeType::NameAttr, Some(name.clone().into())),
            (FileAttributeType::CompressedSizeAttr, Some((container_bytes.len() as i64).into())),
            (
                FileAttributeType::ModifiedDateAttr,
                (mtime != 0).then(|| FileAttributeValue::Date(mtime * 1000)),
            ),
            (FileAttributeType::CommentAttr, comment.map(Into::into)),
        ]);
        attrs.add(FileAttributeType::SizeAttr, Some((payload.len() as i64).into()));

        let provider = MemProvider::new(payload, None);
        GZipFileSystem::new(container_fsrl.make_nested(GZipFileSystem::FS_TYPE), Rc::new(provider), &name, attrs)
    }

    #[test]
    fn annotation_metadata() {
        let fs = mount(&gzip(PAYLOAD));
        assert_eq!(fs.get_type(), "gzip");
        assert_eq!(fs.get_description(), "GZIP");
        assert_eq!(GZipFileSystem::PRIORITY, -10);
        assert_eq!(fs.get_name(), "fox.txt.gz");
    }

    #[test]
    fn listing_shows_single_payload_with_header_name_and_size() {
        let fs = mount(&gzip(PAYLOAD));
        let listing = fs.get_listing(None).unwrap();
        assert_eq!(listing.len(), 1);
        let f = listing[0];
        assert_eq!(f.get_name(), "fox.txt");
        assert_eq!(f.get_path(), "/fox.txt");
        assert_eq!(f.get_length(), PAYLOAD.len() as i64);
        assert_eq!(f.get_fsrl().to_string(), "file:///tmp/fox.txt.gz|gzip:///fox.txt");
        assert_eq!(fs.get_file_count(), 1);
    }

    #[test]
    fn payload_content_round_trips() {
        let fs = mount(&gzip(PAYLOAD));
        let monitor = DummyMonitor;
        let f = fs.lookup(Some("/fox.txt")).unwrap();
        let bp = fs.get_byte_provider(f, &monitor).unwrap();
        assert_eq!(bp.length(), PAYLOAD.len() as u64);
        assert_eq!(bp.read_bytes(0, bp.length()).unwrap(), PAYLOAD);
    }

    #[test]
    fn payload_attributes_reflect_gzip_header() {
        let container = gzip(PAYLOAD);
        let fs = mount(&container);
        let monitor = DummyMonitor;
        let f = fs.get_payload_file().unwrap();
        let attrs = fs.get_file_attributes(f, &monitor);
        assert_eq!(attrs.get_str(FileAttributeType::CommentAttr, ""), "a comment");
        assert_eq!(attrs.get_long(FileAttributeType::SizeAttr, -1), PAYLOAD.len() as i64);
        assert_eq!(
            attrs.get_long(FileAttributeType::CompressedSizeAttr, -1),
            container.len() as i64
        );
        assert!(attrs.contains(FileAttributeType::ModifiedDateAttr));
    }

    #[test]
    fn close_then_everything_is_gone() {
        let mut fs = mount(&gzip(PAYLOAD));
        fs.close().unwrap();
        assert!(fs.is_closed());
        assert!(fs.lookup(Some("/fox.txt")).is_none());
        assert!(fs.get_listing(None).is_err());
    }
}
