pub mod dyld_chained_fixup_header;
pub mod dyld_chained_fixups;
pub mod dyld_chained_fixups_command;
pub mod dyld_chained_import;
pub mod dyld_chained_imports;
pub mod dyld_chained_starts_in_image;
pub mod dyld_chained_starts_in_segment;

/// `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsOffsets` is a
/// byte-for-byte copy of `ghidra.app.util.bin.format.macho.dyld.DyldChainedStartsOffsets` (only
/// the package differs); both Java classes map to the one Rust port.
pub mod dyld_chained_starts_offsets {
    pub use crate::format::macho::dyld::dyld_chained_starts_offsets::DyldChainedStartsOffsets;

    #[cfg(test)]
    mod tests {
        use super::DyldChainedStartsOffsets;
        use crate::app::util::bin::binary_reader::BinaryReader;

        #[test]
        fn chained_package_alias_parses() {
            let mut b = Vec::new();
            for v in [1u32, 1, 0x40] {
                b.extend(v.to_le_bytes());
            }
            let s = DyldChainedStartsOffsets::new(&mut BinaryReader::from_bytes(b, true)).unwrap();
            assert_eq!(s.get_starts_count(), 1);
            assert_eq!(s.get_chain_start_offsets(), [0x40]);
        }
    }
}
