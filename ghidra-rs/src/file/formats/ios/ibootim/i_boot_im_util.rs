use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

use super::i_boot_im_constants;

/// Utility functions for Apple iBootIm image files.
///
/// Mirrors `ghidra.file.formats.ios.ibootim.iBootImUtil`.
pub struct IBootImUtil;

impl IBootImUtil {
    /// Determines whether the given program contains an iBootIm image.
    ///
    /// Checks if the first 8 bytes of the program memory match the iBootIm signature.
    pub fn is_ibootim(program: &ProgramDB) -> bool {
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
                let mut bytes = vec![0u8; i_boot_im_constants::SIGNATURE_LENGTH];
                let bytes_read = memory_guard.get_bytes(&min_address, &mut bytes);
                (bytes_read, bytes)
            })
        };

        if let Some((bytes_read, bytes)) = memory_read_result {
            return bytes_read == i_boot_im_constants::SIGNATURE_LENGTH
                && &bytes[..] == &i_boot_im_constants::SIGNATURE_BYTES;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_can_be_constructed() {
        let _util = IBootImUtil;
    }

    #[test]
    fn is_ibootim_returns_false_when_program_has_no_address_factory() {
        use crate::program::model::lang::sleigh::SleighLanguage;
        use std::sync::Arc;

        let language = Arc::new(SleighLanguage::default());
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => {
                return;
            }
        };

        assert!(!IBootImUtil::is_ibootim(&program));
    }
}
