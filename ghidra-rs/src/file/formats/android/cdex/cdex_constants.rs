use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

/// Android Compact Dex (.CDEX) format constants.
///
/// CompactDex is a currently ART-internal dex file format that aims to reduce
/// storage/RAM usage.
///
/// Reference: <https://android.googlesource.com/platform/art/+/master/runtime/dex/compact_dex_file.h>
///
/// Mirrors `ghidra.file.formats.android.cdex.CDexConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CDexConstants;

impl CDexConstants {
    pub const NAME: &'static str = "Compact Dalvik Executable (CDEX)";
    pub const MAGIC: &'static str = "cdex";
    pub const VERSION_001: &'static str = "001";
    pub const VERSION_002: &'static str = "002";

    /// Returns true if the given ProgramDB contains CDEX information.
    pub fn is_cdex(program: &ProgramDB) -> bool {
        let factory = match program.get_address_factory() {
            Some(f) => f,
            None => return false,
        };

        let default_space = match factory.get_default_address_space() {
            Some(s) => s,
            None => return false,
        };

        let min_address = default_space.min_address();

        let memory_read_result = {
            let memory = program.get_memory();
            memory.read().ok().map(|memory_guard| {
                let mut bytes = vec![0u8; Self::MAGIC.len()];
                let bytes_read = memory_guard.get_bytes(&min_address, &mut bytes);
                (bytes_read, bytes)
            })
        };

        if let Some((bytes_read, bytes)) = memory_read_result {
            return bytes_read == Self::MAGIC.len() && Self::MAGIC.as_bytes() == &bytes[..];
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_value() {
        assert_eq!(CDexConstants::NAME, "Compact Dalvik Executable (CDEX)");
    }

    #[test]
    fn magic_value() {
        assert_eq!(CDexConstants::MAGIC, "cdex");
    }

    #[test]
    fn magic_length() {
        assert_eq!(CDexConstants::MAGIC.len(), 4);
    }

    #[test]
    fn version_001_value() {
        assert_eq!(CDexConstants::VERSION_001, "001");
    }

    #[test]
    fn version_002_value() {
        assert_eq!(CDexConstants::VERSION_002, "002");
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(CDexConstants::default(), CDexConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = CDexConstants;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn constants_are_distinct() {
        assert_ne!(CDexConstants::NAME, CDexConstants::MAGIC);
        assert_ne!(CDexConstants::VERSION_001, CDexConstants::VERSION_002);
    }
}
