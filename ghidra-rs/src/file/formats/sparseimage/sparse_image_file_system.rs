//! Port of `ghidra.file.formats.sparseimage.SparseImageFileSystem`.
//!
//! A pseudo-filesystem holding the expanded contents of an Android sparse image (`simg`). The
//! expansion happens in `SparseImageFileSystemFactory` via `SparseImageDecompressor`; this
//! type only presents the result.

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

/// A pseudo-filesystem that contains a single file that represents the expanded contents of
/// an Android sparse image.
///
/// Mirrors `ghidra.file.formats.sparseimage.SparseImageFileSystem`; all behaviour comes from
/// the embedded [`AbstractSinglePayloadFileSystemBase`], reachable through `Deref`.
pub struct SparseImageFileSystem {
    base: AbstractSinglePayloadFileSystemBase,
}

impl SparseImageFileSystem {
    /// `@FileSystemInfo(type = "simg")`.
    pub const FS_TYPE: &'static str = "simg";
    /// `@FileSystemInfo(description = "Android Sparse Image (simg)")`.
    pub const DESCRIPTION: &'static str = "Android Sparse Image (simg)";
    /// `@FileSystemInfo` default priority.
    pub const PRIORITY: i32 = PRIORITY_DEFAULT;

    /// Creates the filesystem over an already-decompressed payload.
    ///
    /// Mirrors `SparseImageFileSystem(FSRLRoot, ByteProvider, String, FileAttributes)`.
    pub fn new(
        fs_fsrl: FsrlRoot,
        payload_provider: Rc<dyn ByteProvider>,
        payload_filename: &str,
        payload_attrs: FileAttributes,
    ) -> Self {
        SparseImageFileSystem {
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

impl SinglePayloadFileSystem for SparseImageFileSystem {
    const INFO: FileSystemInfo = FileSystemInfo::with(Self::FS_TYPE, Self::DESCRIPTION, Self::PRIORITY);

    fn base(&self) -> &AbstractSinglePayloadFileSystemBase {
        &self.base
    }
}

impl Deref for SparseImageFileSystem {
    type Target = AbstractSinglePayloadFileSystemBase;
    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl DerefMut for SparseImageFileSystem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::filesystem::gfilesystem::abstract_single_payload_file_system::test_support::MemProvider;
    use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::filesystem::gfilesystem::g_file::GFile;
    use crate::util::task::DummyMonitor;

    /// Builds the filesystem the way `SparseImageFileSystemFactory.create` does: the payload
    /// is named after the container with ".raw" appended, sized to the expanded image.
    fn mount(expanded: Vec<u8>) -> SparseImageFileSystem {
        let container = Fsrl::from_string("file:///imgs/system.img").unwrap();
        let len = expanded.len() as i64;
        let attrs = FileAttributes::of([(FileAttributeType::SizeAttr, Some(len.into()))]);
        SparseImageFileSystem::new(
            container.make_nested(SparseImageFileSystem::FS_TYPE),
            Rc::new(MemProvider::new(expanded, None)),
            "system.img.raw",
            attrs,
        )
    }

    #[test]
    fn annotation_metadata() {
        let fs = mount(vec![0u8; 8]);
        assert_eq!(fs.get_type(), "simg");
        assert_eq!(fs.get_description(), "Android Sparse Image (simg)");
        assert_eq!(SparseImageFileSystem::PRIORITY, 0);
        assert_eq!(fs.get_name(), "system.img");
    }

    #[test]
    fn listing_and_content_round_trip() {
        let expanded: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let fs = mount(expanded.clone());
        let listing = fs.get_listing(None).unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].get_name(), "system.img.raw");
        assert_eq!(listing[0].get_length(), 4096);
        let monitor = DummyMonitor;
        let bp = fs.get_byte_provider(listing[0], &monitor).unwrap();
        assert_eq!(bp.read_bytes(0, 4096).unwrap(), expanded);
        assert_eq!(
            fs.get_file_attributes(listing[0], &monitor).get_long(FileAttributeType::SizeAttr, -1),
            4096
        );
    }

    #[test]
    fn tiny_sparse_image_expands_into_payload() {
        use crate::file::formats::sparseimage::sparse_constants::{CHUNK_TYPE_DONT_CARE, CHUNK_TYPE_RAW};
        use crate::file::formats::sparseimage::sparse_image_decompressor::SparseImageDecompressor;
        use crate::format::macos::test_support::VecReader;

        let mut img = Vec::new();
        for v in [0xED26_FF3Au32] {
            img.extend_from_slice(&v.to_le_bytes());
        }
        for v in [1u16, 0, 28, 12] {
            img.extend_from_slice(&v.to_le_bytes());
        }
        for v in [4u32, 2, 2, 0] {
            img.extend_from_slice(&v.to_le_bytes());
        }
        for (ty, sz, body) in [(CHUNK_TYPE_RAW, 1u32, &b"abcd"[..]), (CHUNK_TYPE_DONT_CARE, 1, &[][..])] {
            img.extend_from_slice(&ty.to_le_bytes());
            img.extend_from_slice(&0u16.to_le_bytes());
            img.extend_from_slice(&sz.to_le_bytes());
            img.extend_from_slice(&(12 + body.len() as u32).to_le_bytes());
            img.extend_from_slice(body);
        }
        let mut reader = VecReader::little_endian(img);
        let mut expanded = Vec::new();
        SparseImageDecompressor::new(&mut reader, &mut expanded).decompress(&DummyMonitor).unwrap();

        let fs = mount(expanded);
        let monitor = DummyMonitor;
        let f = fs.lookup(Some("/system.img.raw")).unwrap();
        assert_eq!(f.get_length(), 8);
        let bp = fs.get_byte_provider(f, &monitor).unwrap();
        assert_eq!(bp.read_bytes(0, 8).unwrap(), b"abcd\0\0\0\0");
    }
}
