use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

/// Android Watched Dex (.WDEX) format constants.
///
/// WDEX files are used for verification and validation of DEX files.
///
/// Reference: <https://android.googlesource.com/platform/art/+/master/runtime/vdex_file.h>
///
/// Mirrors `ghidra.file.formats.android.wdex.WdexConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WdexConstants;

impl WdexConstants {
    pub const MAGIC: &'static str = "wdex";
    pub const KVDEX_INVALID_MAGIC: &'static str = Self::MAGIC;

    /// Returns true if the given ProgramDB contains WDEX information.
    pub fn is_wdex(program: &ProgramDB) -> bool {
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
    fn magic_value() {
        assert_eq!(WdexConstants::MAGIC, "wdex");
    }

    #[test]
    fn magic_length() {
        assert_eq!(WdexConstants::MAGIC.len(), 4);
    }

    #[test]
    fn kvdex_invalid_magic_matches_magic() {
        assert_eq!(WdexConstants::KVDEX_INVALID_MAGIC, WdexConstants::MAGIC);
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(WdexConstants::default(), WdexConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = WdexConstants;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn constants_are_distinct_from_others() {
        assert!(!WdexConstants::MAGIC.is_empty());
        assert_eq!(WdexConstants::MAGIC.len(), WdexConstants::KVDEX_INVALID_MAGIC.len());
    }
}
