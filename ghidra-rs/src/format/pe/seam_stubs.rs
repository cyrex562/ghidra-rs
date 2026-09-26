//! Minimal placeholder types for `ghidra.app.util.bin.format.pe` classes referenced by a ported
//! type before the real Rust port of that class exists yet.
//!
//! This is a SEPARATE file from the crate-wide `crate::format::seam_stubs`, which already hosts
//! several PE placeholders (`NTHeader`, `FileHeader`, `OptionalHeader`, ...). It exists because
//! `ghidra.app.util.bin.format.pe.SectionHeader` and `ghidra.app.util.bin.format.pe.pef.SectionHeader`
//! are two distinct Java classes with the same simple name; the PEF one is already declared as
//! `pub trait SectionHeader` in `crate::format::seam_stubs`, so the PE one cannot also live there
//! without a name collision. Keep any future PE-only placeholder that would collide with an
//! existing `format::seam_stubs` name in this file instead. See `STUBS.tsv` for provenance.

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::NTHeader;

/// Placeholder for `ghidra.app.util.bin.format.pe.SectionHeader`, referenced by
/// [`LoadConfigDirectory`](crate::format::pe::load_config_directory::LoadConfigDirectory) before
/// the real class is ported. Only the two accessors needed to locate the Dynamic Value
/// Relocation Table from a section index.
///
/// Not to be confused with `ghidra.app.util.bin.format.pe.pef.SectionHeader`, which is the
/// unrelated PEF-format placeholder `pub trait SectionHeader` in `crate::format::seam_stubs`.
pub trait SectionHeader: Send + Sync {
    /// `SectionHeader.getVirtualAddress()`.
    fn get_virtual_address(&self) -> i32;
    /// `SectionHeader.getPointerToRawData()`.
    fn get_pointer_to_raw_data(&self) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.dvrt.ImageDynamicRelocationTable`, referenced
/// by [`LoadConfigDirectory`](crate::format::pe::load_config_directory::LoadConfigDirectory)
/// before the real class is ported. Records only what `LoadConfigDirectory` captures at
/// construction time (the RVA of the table and whether the image is 64-bit); does not parse the
/// dynamic value relocation entries themselves yet.
pub struct ImageDynamicRelocationTable {
    pub rva: i64,
    pub is64bit: bool,
}

impl ImageDynamicRelocationTable {
    /// Port of `ImageDynamicRelocationTable(BinaryReader, long, boolean)`, minus the actual
    /// relocation-block parsing.
    pub fn new(_reader: &mut dyn BinaryReader, rva: i64, is64bit: bool) -> std::io::Result<Self> {
        Ok(ImageDynamicRelocationTable { rva, is64bit })
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pe.chpe.ImageChpeMetadataX86`, referenced by
/// [`LoadConfigDirectory`](crate::format::pe::load_config_directory::LoadConfigDirectory) before
/// the real class is ported. Records only the pointer `LoadConfigDirectory` captures; does not
/// parse the CHPE range table itself yet.
pub struct ImageChpeMetadataX86 {
    pub chpe_metadata_pointer: i64,
}

impl ImageChpeMetadataX86 {
    /// Port of `ImageChpeMetadataX86(BinaryReader, NTHeader, long)`, minus the actual CHPE range
    /// table parsing.
    pub fn new(
        _reader: &mut dyn BinaryReader,
        _nt: &dyn NTHeader,
        chpe_metadata_pointer: i64,
    ) -> std::io::Result<Self> {
        Ok(ImageChpeMetadataX86 { chpe_metadata_pointer })
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pe.chpe.ImageArm64ecMetadata`, referenced by
/// [`LoadConfigDirectory`](crate::format::pe::load_config_directory::LoadConfigDirectory) before
/// the real class is ported. Records only the pointer `LoadConfigDirectory` captures; does not
/// parse the ARM64EC metadata table itself yet.
pub struct ImageArm64ecMetadata {
    pub chpe_metadata_pointer: i64,
}

impl ImageArm64ecMetadata {
    /// Port of `ImageArm64ecMetadata(BinaryReader, NTHeader, long)`, minus the actual ARM64EC
    /// metadata table parsing.
    pub fn new(
        _reader: &mut dyn BinaryReader,
        _nt: &dyn NTHeader,
        chpe_metadata_pointer: i64,
    ) -> std::io::Result<Self> {
        Ok(ImageArm64ecMetadata { chpe_metadata_pointer })
    }
}
