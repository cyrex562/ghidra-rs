/// 64-bit ordinal flag (high bit of a 64-bit import thunk).
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// 32-bit ordinal flag (high bit of a 32-bit import thunk).
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;

/// Magic number for PE files ("PE\0\0").
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

/// Magic number for OS/2 (NE) files.
pub const IMAGE_OS2_SIGNATURE: u32 = 0x454E;

/// Magic number for little-endian OS/2 (LE) files.
pub const IMAGE_OS2_SIGNATURE_LE: u32 = 0x454C;

/// Magic number for VXD files.
pub const IMAGE_VXD_SIGNATURE: u32 = 0x454C;

/// Optional header magic number for 32-bit PE files.
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;

/// Optional header magic number for 64-bit PE+ files.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

/// Optional header magic number for ROM images.
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

/// Size of the ROM optional header, in bytes.
pub const IMAGE_SIZEOF_ROM_OPTIONAL_HEADER: u32 = 56;

/// Size of the standard optional header fields, in bytes.
pub const IMAGE_SIZEOF_STD_OPTIONAL_HEADER: u32 = 28;

/// Size of the 32-bit optional header, in bytes.
pub const IMAGE_SIZEOF_NT_OPTIONAL32_HEADER: u32 = 224;

/// Size of the 64-bit optional header, in bytes.
pub const IMAGE_SIZEOF_NT_OPTIONAL64_HEADER: u32 = 240;

/// Number of bytes in the archive start magic string.
pub const IMAGE_ARCHIVE_START_SIZE: u8 = 8;

/// Archive start magic value.
pub const IMAGE_ARCHIVE_START: &str = "!<arch>\n";

/// Archive end-of-member magic value.
pub const IMAGE_ARCHIVE_END: &str = "`\n";

/// Archive member padding byte.
pub const IMAGE_ARCHIVE_PAD: &str = "\n";

/// Archive linker member name (padded to 16 chars).
pub const IMAGE_ARCHIVE_LINKER_MEMBER: &str = "/               ";

/// Archive long-names member name (padded to 16 chars).
pub const IMAGE_ARCHIVE_LONGNAMES_MEMBER: &str = "//              ";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_flags() {
        assert_eq!(IMAGE_ORDINAL_FLAG64, 0x8000000000000000u64);
        assert_eq!(IMAGE_ORDINAL_FLAG32, 0x80000000u32);
    }

    #[test]
    fn nt_signature() {
        assert_eq!(IMAGE_NT_SIGNATURE, 0x0000_4550);
        // "PE\0\0" in little-endian
        let bytes = IMAGE_NT_SIGNATURE.to_le_bytes();
        assert_eq!(&bytes[..2], b"PE");
    }

    #[test]
    fn os2_signatures() {
        assert_eq!(IMAGE_OS2_SIGNATURE, 0x454E);
        assert_eq!(IMAGE_OS2_SIGNATURE_LE, 0x454C);
        assert_eq!(IMAGE_VXD_SIGNATURE, 0x454C);
        // LE and VXD share the same value
        assert_eq!(IMAGE_OS2_SIGNATURE_LE, IMAGE_VXD_SIGNATURE);
    }

    #[test]
    fn optional_header_magic() {
        assert_eq!(IMAGE_NT_OPTIONAL_HDR32_MAGIC, 0x10B);
        assert_eq!(IMAGE_NT_OPTIONAL_HDR64_MAGIC, 0x20B);
        assert_eq!(IMAGE_ROM_OPTIONAL_HDR_MAGIC, 0x107);
    }

    #[test]
    fn optional_header_sizes() {
        assert_eq!(IMAGE_SIZEOF_ROM_OPTIONAL_HEADER, 56);
        assert_eq!(IMAGE_SIZEOF_STD_OPTIONAL_HEADER, 28);
        assert_eq!(IMAGE_SIZEOF_NT_OPTIONAL32_HEADER, 224);
        assert_eq!(IMAGE_SIZEOF_NT_OPTIONAL64_HEADER, 240);
    }

    #[test]
    fn archive_constants() {
        assert_eq!(IMAGE_ARCHIVE_START_SIZE, 8);
        assert_eq!(IMAGE_ARCHIVE_START.len(), 8);
        assert_eq!(IMAGE_ARCHIVE_START, "!<arch>\n");
        assert_eq!(IMAGE_ARCHIVE_END, "`\n");
        assert_eq!(IMAGE_ARCHIVE_PAD, "\n");
        assert_eq!(IMAGE_ARCHIVE_LINKER_MEMBER.len(), 16);
        assert_eq!(IMAGE_ARCHIVE_LINKER_MEMBER, "/               ");
        assert_eq!(IMAGE_ARCHIVE_LONGNAMES_MEMBER.len(), 16);
        assert_eq!(IMAGE_ARCHIVE_LONGNAMES_MEMBER, "//              ");
    }
}
