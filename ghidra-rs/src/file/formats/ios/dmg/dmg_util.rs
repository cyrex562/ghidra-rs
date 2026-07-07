use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

use super::dmg_constants;

/// Utility functions for Apple Disk Image (DMG) files.
///
/// Mirrors `ghidra.file.formats.ios.dmg.DmgUtil`.
pub struct DmgUtil;

impl DmgUtil {
    /// Determines whether the given program contains a DMG file.
    ///
    /// Checks if the first 8 bytes of the program memory match either DMG v1 or v2 magic bytes.
    pub fn is_dmg(program: &ProgramDB) -> bool {
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
                let mut bytes = vec![0u8; dmg_constants::DMG_MAGIC_LENGTH];
                let bytes_read = memory_guard.get_bytes(&min_address, &mut bytes);
                (bytes_read, bytes)
            })
        };

        if let Some((bytes_read, bytes)) = memory_read_result {
            return bytes_read == dmg_constants::DMG_MAGIC_LENGTH
                && (&bytes[..] == &dmg_constants::DMG_MAGIC_BYTES_V1
                    || &bytes[..] == &dmg_constants::DMG_MAGIC_BYTES_V2);
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_can_be_constructed() {
        let _util = DmgUtil;
    }

    #[test]
    fn is_dmg_returns_false_when_program_has_no_address_factory() {
        use crate::program::model::lang::sleigh::SleighLanguage;
        use std::sync::Arc;

        let language = Arc::new(SleighLanguage::default());
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => {
                return;
            }
        };

        assert!(!DmgUtil::is_dmg(&program));
    }
}
