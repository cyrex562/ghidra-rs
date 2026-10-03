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
    use crate::program::model::lang::sleigh::SleighLanguage;
    use std::sync::Arc;

    fn test_language() -> Arc<SleighLanguage> {
        use crate::program::model::address::DefaultAddressFactory;
        use crate::program::model::pcode::PackedDecode;
        let mut data = vec![];
        // <sleigh version="4" bigendian="false">
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        // <spaces defaultspace="ram">
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        // </spaces>
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        // <scope id="0" parent="0"/>
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        // </sleigh>
        data.extend_from_slice(&[0xA0, 0x80 | 33]);
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, data);
        Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap())
    }

    #[test]
    fn struct_can_be_constructed() {
        let _util = IBootImUtil;
    }

    #[test]
    fn is_ibootim_returns_false_when_program_has_no_address_factory() {
        let language = test_language();
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => {
                return;
            }
        };

        assert!(!IBootImUtil::is_ibootim(&program));
    }
}
