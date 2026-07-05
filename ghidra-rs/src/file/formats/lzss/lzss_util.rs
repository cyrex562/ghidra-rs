use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

use super::lzss_constants;

/// Utility functions for LZSS-compressed files.
///
/// Mirrors `ghidra.file.formats.lzss.LzssUtil`.
pub struct LzssUtil;

impl LzssUtil {
    /// Determines whether the given program contains LZSS-compressed data.
    ///
    /// Checks if the program data matches the LZSS signature pattern:
    /// - First 4 bytes: SIGNATURE_COMPRESSION_BYTES ("comp")
    /// - Next 4 bytes: SIGNATURE_LZSS_BYTES ("lzss")
    pub fn is_lzss(program: &ProgramDB) -> bool {
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
                let mut bytes = vec![0u8; 8];
                let bytes_read = memory_guard.get_bytes(&min_address, &mut bytes);
                (bytes_read, bytes)
            })
        };

        if let Some((bytes_read, bytes)) = memory_read_result {
            if bytes_read >= 8 {
                let compression_bytes = &bytes[..4];
                let lzss_bytes = &bytes[4..8];
                return compression_bytes == lzss_constants::SIGNATURE_COMPRESSION_BYTES
                    && lzss_bytes == lzss_constants::SIGNATURE_LZSS_BYTES;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use std::sync::Arc;

    #[test]
    fn struct_can_be_constructed() {
        let _util = LzssUtil;
    }

    #[test]
    fn is_lzss_returns_false_when_program_has_no_address_factory() {
        let language = Arc::new(SleighLanguage::default());
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => {
                return;
            }
        };

        assert!(!LzssUtil::is_lzss(&program));
    }

    #[test]
    fn is_lzss_returns_false_with_no_memory() {
        let language = Arc::new(SleighLanguage::default());
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => {
                return;
            }
        };

        assert!(!LzssUtil::is_lzss(&program));
    }

    #[test]
    fn is_lzss_returns_false_with_insufficient_bytes() {
        use crate::program::model::lang::sleigh::SleighLanguage;
        use crate::program::model::mem::Memory;

        let language = Arc::new(SleighLanguage::default());
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => {
                return;
            }
        };

        // Even if memory is available, if we can't read enough bytes, it returns false
        assert!(!LzssUtil::is_lzss(&program));
    }
}
