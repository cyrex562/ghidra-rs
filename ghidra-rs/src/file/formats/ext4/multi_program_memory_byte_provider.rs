use std::io;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

/// A read-only [`ByteProvider`] that concatenates the default-space memory of
/// up to three programs, treating each program's memory as if it started at
/// offset 0.
///
/// Mirrors `ghidra.file.formats.ext4.MultiProgramMemoryByteProvider`. The
/// Java source's three overloaded constructors (one, two, or three programs)
/// collapse into a single [`Self::new`] taking a `Vec`.
pub struct MultiProgramMemoryByteProvider<'a> {
    programs: Vec<&'a ProgramDB>,
    base_addresses: Vec<Address>,
}

impl<'a> MultiProgramMemoryByteProvider<'a> {
    /// Creates a provider over `programs`, each treated as starting at
    /// offset 0 in its own default address space. Returns `None` if any
    /// program lacks an address factory or default address space.
    pub fn new(programs: Vec<&'a ProgramDB>) -> Option<Self> {
        let mut base_addresses = Vec::with_capacity(programs.len());
        for program in &programs {
            let space = program.get_address_factory()?.get_default_address_space()?;
            base_addresses.push(space.address(0));
        }
        Some(MultiProgramMemoryByteProvider { programs, base_addresses })
    }
}

impl<'a> ByteProvider for MultiProgramMemoryByteProvider<'a> {
    fn length(&mut self) -> io::Result<u64> {
        let mut total = 0u64;
        for program in &self.programs {
            let memory = program.get_memory();
            let memory = memory
                .read()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "memory lock poisoned"))?;
            total += memory.size();
        }
        Ok(total)
    }

    /// Mirrors the Java source: returns as soon as any program's base
    /// address survives the `add`, even when that program's memory doesn't
    /// actually contain the resulting address. It never falls through to try
    /// the next program's memory -- a latent bug preserved here for parity.
    fn is_valid_index(&mut self, index: u64) -> bool {
        let Ok(displacement) = i64::try_from(index) else {
            return false;
        };
        for (program, base) in self.programs.iter().zip(&self.base_addresses) {
            if let Ok(index_address) = base.add(displacement) {
                let memory = program.get_memory();
                let memory = memory.read().unwrap();
                return memory.contains(&index_address);
            }
        }
        false
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        if let Ok(displacement) = i64::try_from(index) {
            for (program, base) in self.programs.iter().zip(&self.base_addresses) {
                if let Ok(addr) = base.add(displacement) {
                    let memory = program.get_memory();
                    let memory = memory.read().unwrap();
                    if let Ok(byte) = memory.get_byte(&addr) {
                        return Ok(byte);
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Unable to read byte at index: {index}"),
        ))
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        if let Ok(displacement) = i64::try_from(index) {
            for (program, base) in self.programs.iter().zip(&self.base_addresses) {
                if let Ok(addr) = base.add(displacement) {
                    let memory = program.get_memory();
                    let memory = memory.read().unwrap();
                    let mut bytes = vec![0u8; length];
                    let n_read = memory.get_bytes(&addr, &mut bytes);
                    if n_read == length {
                        return Ok(bytes);
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Unable to read {length} bytes at index {index}"),
        ))
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MultiProgramMemoryByteProvider does not support writes",
        ))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MultiProgramMemoryByteProvider does not support writes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::mem::{MemoryAccessException, MemoryBlock};
    use crate::program::model::pcode::PackedDecode;
    use std::sync::{Arc, RwLock};

    struct FakeMemoryBlock {
        start: Address,
        data: Vec<u8>,
    }

    impl MemoryBlock for FakeMemoryBlock {
        fn get_name(&self) -> &str {
            "test_block"
        }

        fn get_start(&self) -> Address {
            self.start.clone()
        }

        fn get_end(&self) -> Address {
            self.start.add(self.data.len() as i64 - 1).unwrap()
        }

        fn get_size(&self) -> u64 {
            self.data.len() as u64
        }

        fn is_initialized(&self) -> bool {
            true
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.subtract(&self.start) as usize;
            self.data
                .get(offset)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.subtract(&self.start) as usize;
            let available = self.data.len().saturating_sub(offset);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[offset..offset + n]);
            n
        }

        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let offset = addr.subtract(&self.start) as usize;
            self.data[offset..offset + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    fn test_language() -> Arc<SleighLanguage> {
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

    fn program_with_block(name: &str, language: &Arc<SleighLanguage>, data: Vec<u8>) -> ProgramDB {
        let program = ProgramDB::new(name.to_string(), language.clone()).unwrap();
        let space = language
            .get_address_factory()
            .get_address_space_by_name("ram")
            .unwrap();
        let start = space.address(0);
        let block = Arc::new(RwLock::new(FakeMemoryBlock { start, data }));
        program.get_memory().write().unwrap().add_block(block);
        program
    }

    #[test]
    fn length_sums_across_all_programs() {
        let language = test_language();
        let p1 = program_with_block("p1", &language, vec![1, 2]);
        let p2 = program_with_block("p2", &language, vec![3, 4, 5]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1, &p2]).unwrap();
        assert_eq!(provider.length().unwrap(), 5);
    }

    #[test]
    fn read_byte_falls_through_to_second_program() {
        let language = test_language();
        let p1 = program_with_block("p1", &language, vec![0xAA, 0xBB]);
        let p2 = program_with_block("p2", &language, vec![0, 0, 0, 0, 0, 0xCC]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1, &p2]).unwrap();

        // Index 0 is served by the first program.
        assert_eq!(provider.read_byte(0).unwrap(), 0xAA);
        // Index 5 is out of range for the first program's block, so the
        // read falls through to the second program's memory at offset 5.
        assert_eq!(provider.read_byte(5).unwrap(), 0xCC);
    }

    #[test]
    fn read_byte_out_of_range_of_all_programs_errors() {
        let language = test_language();
        let p1 = program_with_block("p1", &language, vec![1, 2]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1]).unwrap();
        assert!(provider.read_byte(100).is_err());
    }

    #[test]
    fn read_bytes_falls_through_when_short_read() {
        let language = test_language();
        let p1 = program_with_block("p1", &language, vec![1, 2]);
        let p2 = program_with_block("p2", &language, vec![10, 20, 30]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1, &p2]).unwrap();

        // A 3-byte read at index 0 doesn't fully fit in program1's 2-byte
        // block, so it falls through and is served entirely by program2.
        assert_eq!(provider.read_bytes(0, 3).unwrap(), vec![10, 20, 30]);
    }

    #[test]
    fn is_valid_index_true_within_first_program() {
        let language = test_language();
        let p1 = program_with_block("p1", &language, vec![1, 2]);
        let p2 = program_with_block("p2", &language, vec![10, 20, 30]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1, &p2]).unwrap();
        assert!(provider.is_valid_index(0));
    }

    #[test]
    fn is_valid_index_does_not_fall_through_to_second_program() {
        let language = test_language();
        // program1's base address survives `add(2)` (2 is a valid offset in
        // its address space) even though its block doesn't cover it, so the
        // Java-parity early return reports false instead of checking
        // program2, which does have valid memory at that offset.
        let p1 = program_with_block("p1", &language, vec![1, 2]);
        let p2 = program_with_block("p2", &language, vec![10, 20, 30]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1, &p2]).unwrap();
        assert!(!provider.is_valid_index(2));
    }

    #[test]
    fn write_byte_is_unsupported() {
        let language = test_language();
        let p1 = program_with_block("p1", &language, vec![1, 2]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1]).unwrap();
        let err = provider.write_byte(0, 0xFF).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn write_bytes_is_unsupported() {
        let language = test_language();
        let p1 = program_with_block("p1", &language, vec![1, 2]);
        let mut provider = MultiProgramMemoryByteProvider::new(vec![&p1]).unwrap();
        let err = provider.write_bytes(0, &[0xFF]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
