//! Test-only readers and fixtures shared by the macOS resource-fork / AppleSingleDouble / CFM
//! tests.

use crate::app::util::bin::binary_reader::BinaryReader;

/// A big-endian reader over `bytes` (resource forks and CFM are big-endian).
pub(crate) fn be_reader(bytes: Vec<u8>) -> BinaryReader {
    BinaryReader::from_bytes(bytes, false)
}

/// A little-endian reader over `bytes`.
pub(crate) fn le_reader(bytes: Vec<u8>) -> BinaryReader {
    BinaryReader::from_bytes(bytes, true)
}

/// Big-endian byte-image builder for the fixtures.
#[derive(Default)]
pub(crate) struct Image(pub(crate) Vec<u8>);

impl Image {
    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    pub(crate) fn pad_to(&mut self, len: usize) -> &mut Self {
        assert!(self.0.len() <= len, "image already past {len:#x}");
        self.0.resize(len, 0);
        self
    }
}

/// A resource fork at offset 0 whose map (at 0x20) holds two types:
///
/// * `'STR '` with one resource (ID 128, named "hello", attributes 0x20, data offset 0x10);
/// * `'ICN#'` with two resources (ID 129, unnamed; ID 130, named "icn", data offset 0x10000).
///
/// Map layout: type list offset 0x1e (count word at 0x3e, entries at 0x40), reference lists at
/// 0x50 and 0x5c, name list offset 0x54 (names at 0x74 running to the end of the image).
pub(crate) fn resource_fork_fixture() -> Vec<u8> {
    let mut img = Image::default();
    img.u32(0x100).u32(0x20).u32(0x40).u32(0x5e);
    img.pad_to(0x20);
    // Map header.
    img.u32(0x100).u32(0x20).u32(0x40).u32(0x5e);
    img.u32(0xdead_beef).u16(7).u16(0x80).u16(0x1e).u16(0x54).u16(1);
    // Type list.
    img.u16(1);
    img.bytes(b"STR ").u16(0).u16(0x12);
    img.bytes(b"ICN#").u16(1).u16(0x1e);
    assert_eq!(img.0.len(), 0x50);
    // Reference lists.
    img.u16(128).u16(0).u8(0x20).bytes(&[0, 0, 0x10]).u32(0);
    img.u16(129).u16(0xffff).u8(0).bytes(&[0, 0, 0]).u32(0);
    img.u16(130).u16(6).u8(0).bytes(&[1, 0, 0]).u32(0);
    assert_eq!(img.0.len(), 0x74);
    // Name list.
    img.u8(5).bytes(b"hello").u8(3).bytes(b"icn");
    img.0
}

/// A resource fork preceded by `base` zero bytes, holding a single `'cfrg'` resource whose data
/// (at fork+0x10, after its 4-byte length prefix) is a version-1 `CFragResource` with one member:
/// a `"pwpc"` application fragment named `"App"`.
///
/// Fork layout: data at 0x10, map at 0x70 (type list offset 0x1e, one type entry at 0x90, its
/// reference list at 0x98), empty name list at the end of the image (name list offset 0x34).
pub(crate) fn cfrg_fork_fixture(base: usize) -> Vec<u8> {
    let mut img = Image::default();
    img.pad_to(base);
    img.u32(0x10).u32(0x70).u32(0x54).u32(0x34);
    // Resource data: length prefix, then the CFragResource.
    img.u32(0x50);
    img.u32(0).u32(0).u32(1).u32(0).u32(0).u32(0).u32(0).u32(1);
    cfrag_member(&mut img, b"pwpc", 1, "App", 0x30);
    img.pad_to(base + 0x70);
    // Map.
    img.u32(0x10).u32(0x70).u32(0x54).u32(0x34);
    img.u32(0).u16(0).u16(0).u16(0x1e).u16(0x34).u16(0);
    img.u16(0);
    img.bytes(b"cfrg").u16(0).u16(0x0a);
    img.u16(0).u16(0xffff).u8(0).bytes(&[0, 0, 0]).u32(0);
    assert_eq!(img.0.len(), base + 0xa4);
    img.0
}

/// Appends one `CFragResourceMember` (43 bytes plus the name) with the given architecture, usage
/// byte, name and declared member size. Version fields are 2 (current) and 1 (old definition);
/// `uUsage1` is 0x1000; the locator is 1 (data fork) at offset 0x200, length 0x300.
pub(crate) fn cfrag_member(img: &mut Image, arch: &[u8; 4], usage: u8, name: &str, size: u16) {
    img.bytes(arch).u16(0).u8(0).u8(5);
    img.u32(2).u32(1);
    img.u32(0x1000).u16(0);
    img.u8(usage).u8(1);
    img.u32(0x200).u32(0x300);
    img.u32(0).u16(0);
    img.u16(0).u16(size);
    img.u8(name.len() as u8).bytes(name.as_bytes());
}
