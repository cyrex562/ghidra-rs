use crate::app::util::bin::binary_reader::BinaryReader;
use crate::program::database::program_db::ProgramDB;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

use super::boot_image_constants::BootImageConstants;

/// Utility functions for Android boot images.
///
/// Mirrors `ghidra.file.formats.android.bootimg.BootImageUtil`.
pub struct BootImageUtil;

impl BootImageUtil {
    /// Determines whether the given program's memory starts with the boot image magic.
    pub fn is_boot_image(program: &ProgramDB) -> bool {
        Self::starts_with(program, BootImageConstants::BOOT_MAGIC)
    }

    /// Determines whether the given reader's contents start with the boot image magic.
    pub fn is_boot_image_reader(reader: &dyn BinaryReader) -> bool {
        Self::reader_starts_with(reader, BootImageConstants::BOOT_MAGIC)
    }

    /// Determines whether the given program's memory starts with the vendor boot image magic.
    pub fn is_vendor_boot_image(program: &ProgramDB) -> bool {
        Self::starts_with(program, BootImageConstants::VENDOR_BOOT_MAGIC)
    }

    /// Determines whether the given reader's contents start with the vendor boot image magic.
    pub fn is_vendor_boot_image_reader(reader: &dyn BinaryReader) -> bool {
        Self::reader_starts_with(reader, BootImageConstants::VENDOR_BOOT_MAGIC)
    }

    /// Formats a boot image header's `os_version` field as `A.B.C_Y_M`.
    pub fn get_os_version_string(os_version: i32) -> String {
        let v = os_version as u32;
        let a = (v & 0xfe000000) >> 25;
        let b = (v & 0x01fc0000) >> 18;
        let c = (v & 0x0003f800) >> 11;
        let y = (v & 0x000007f0) >> 4;
        let m = v & 0x0000000f;
        format!("{}.{}.{}_{}_{}", a, b, c, y, m)
    }

    fn starts_with(program: &ProgramDB, magic: &str) -> bool {
        let factory = match program.get_address_factory() {
            Some(f) => f,
            None => return false,
        };

        let default_space = match factory.get_default_address_space() {
            Some(s) => s,
            None => return false,
        };

        let min_address = default_space.min_address();
        let magic_bytes = magic.as_bytes();

        let memory_read_result = {
            let memory = program.get_memory();
            memory.read().ok().map(|memory_guard| {
                let mut bytes = vec![0u8; magic_bytes.len()];
                let bytes_read = memory_guard.get_bytes(&min_address, &mut bytes);
                (bytes_read, bytes)
            })
        };

        if let Some((bytes_read, bytes)) = memory_read_result {
            if bytes_read >= magic_bytes.len() {
                return bytes == magic_bytes;
            }
        }

        false
    }

    fn reader_starts_with(reader: &dyn BinaryReader, magic: &str) -> bool {
        reader
            .read_ascii_string_fixed(0, magic.len())
            .map(|read_magic| read_magic == magic)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;
    use std::sync::Arc;

    struct MockReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, position: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn is_valid_index(&self, index: u64) -> bool {
            (index as usize) < self.bytes.len()
        }

        fn get_pointer_index(&self) -> u64 {
            self.position as u64
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.position;
            self.position = index as usize;
            old as u64
        }

        fn is_little_endian(&self) -> bool {
            false
        }

        fn set_little_endian(&mut self, _is_little_endian: bool) {}

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "index out of range"))
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start
                .checked_add(n_elements)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
            if end > self.bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "range out of bounds",
                ));
            }
            Ok(self.bytes[start..end].to_vec())
        }

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            panic!("not implemented for mock")
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(Self {
                bytes: self.bytes.clone(),
                position: new_index as usize,
            })
        }
    }

    #[test]
    fn struct_can_be_constructed() {
        let _util = BootImageUtil;
    }

    #[test]
    fn is_boot_image_returns_false_when_program_has_no_address_factory() {
        let language = Arc::new(SleighLanguage::default());
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => return,
        };

        assert!(!BootImageUtil::is_boot_image(&program));
    }

    #[test]
    fn is_vendor_boot_image_returns_false_when_program_has_no_address_factory() {
        let language = Arc::new(SleighLanguage::default());
        let program = match ProgramDB::new("test".to_string(), language) {
            Ok(p) => p,
            Err(_) => return,
        };

        assert!(!BootImageUtil::is_vendor_boot_image(&program));
    }

    #[test]
    fn is_boot_image_reader_matches_magic() {
        let mut bytes = BootImageConstants::BOOT_MAGIC.as_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let reader = MockReader::new(bytes);
        assert!(BootImageUtil::is_boot_image_reader(&reader));
    }

    #[test]
    fn is_boot_image_reader_rejects_mismatch() {
        let reader = MockReader::new(b"NOTAMAGIC".to_vec());
        assert!(!BootImageUtil::is_boot_image_reader(&reader));
    }

    #[test]
    fn is_boot_image_reader_rejects_truncated_data() {
        let reader = MockReader::new(b"AND".to_vec());
        assert!(!BootImageUtil::is_boot_image_reader(&reader));
    }

    #[test]
    fn is_vendor_boot_image_reader_matches_magic() {
        let mut bytes = BootImageConstants::VENDOR_BOOT_MAGIC.as_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 8]);
        let reader = MockReader::new(bytes);
        assert!(BootImageUtil::is_vendor_boot_image_reader(&reader));
    }

    #[test]
    fn is_vendor_boot_image_reader_rejects_mismatch() {
        let reader = MockReader::new(BootImageConstants::BOOT_MAGIC.as_bytes().to_vec());
        assert!(!BootImageUtil::is_vendor_boot_image_reader(&reader));
    }

    #[test]
    fn os_version_string_formats_components() {
        // a=7, b=42, c=13, y=99, m=5
        let os_version = (7u32 << 25) | (42u32 << 18) | (13u32 << 11) | (99u32 << 4) | 5u32;
        assert_eq!(
            BootImageUtil::get_os_version_string(os_version as i32),
            "7.42.13_99_5"
        );
    }

    #[test]
    fn os_version_string_zero() {
        assert_eq!(BootImageUtil::get_os_version_string(0), "0.0.0_0_0");
    }

    #[test]
    fn os_version_string_high_bit_set() {
        // a's field occupies the sign bit; ensure unsigned shift semantics are preserved.
        let os_version: u32 = 0xfe000000;
        assert_eq!(
            BootImageUtil::get_os_version_string(os_version as i32),
            "127.0.0_0_0"
        );
    }
}
