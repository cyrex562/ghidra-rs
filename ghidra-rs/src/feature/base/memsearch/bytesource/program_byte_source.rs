//! [`AddressableByteSource`] implementation reading directly from a [`Program`]'s memory.
//!
//! Java source: `ghidra.features.base.memsearch.bytesource.ProgramByteSource`.
//!
//! # Not reproduced: the `MemoryAccessException` catch
//!
//! Java's `getBytes` catches `MemoryAccessException` from `Memory.getBytes` and returns `0`. This
//! port's [`Memory::get_bytes`] trait method already reports a short/zero read by its `usize`
//! return value instead of an exception (matching how
//! [`MemoryBlockDB::get_bytes`](crate::program::database::mem::memory_block_db::MemoryBlockDB)
//! already behaves), so there is nothing to catch -- the `try`/`catch` collapses to a direct call.
use std::sync::Arc;

use crate::feature::base::memsearch::bytesource::addressable_byte_source::{
    generate_program_location, AddressableByteSource,
};
use crate::feature::base::memsearch::bytesource::program_search_region::ProgramSearchRegion;
use crate::feature::base::memsearch::bytesource::search_region::SearchRegion;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;
use crate::program::util::program_location::ProgramLocation;

/// [`AddressableByteSource`] implementation for a Ghidra [`Program`].
///
/// Port of `ghidra.features.base.memsearch.bytesource.ProgramByteSource`.
pub struct ProgramByteSource {
    memory: Arc<dyn Memory>,
}

impl ProgramByteSource {
    /// Constructs a byte source reading from `program`'s memory.
    ///
    /// Port of `ProgramByteSource(Program)`.
    ///
    /// # Panics
    /// Panics if `program` has no memory, mirroring the `NullPointerException` a null `memory`
    /// field would eventually produce in Java (this port's [`Memory`] accessors are non-nullable).
    pub fn new(program: Arc<dyn Program>) -> Self {
        let memory =
            program.get_memory().expect("ProgramByteSource requires a program with memory");
        Self { memory }
    }

    /// The program this byte source reads from.
    ///
    /// Port of `getProgram()`.
    ///
    /// # Panics
    /// Panics if the underlying [`Memory`] cannot report its owning program.
    pub fn get_program(&self) -> Arc<dyn Program> {
        self.memory.get_program().expect("ProgramByteSource's memory has no owning program")
    }
}

impl AddressableByteSource for ProgramByteSource {
    fn get_bytes(&self, address: &Address, bytes: &mut [u8], length: usize) -> usize {
        let len = length.min(bytes.len());
        self.memory.get_bytes(address, &mut bytes[..len])
    }

    fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
        // Mirrors `ProgramSearchRegion.ALL`.
        vec![Box::new(ProgramSearchRegion::Loaded), Box::new(ProgramSearchRegion::Other)]
    }

    fn invalidate(&mut self) {
        // Nothing to do in the static case.
    }

    fn get_canonical_location(&self, address: &Address) -> Box<dyn ProgramLocation> {
        generate_program_location(self.get_program(), address)
    }

    fn rebase_from_canonical(&self, location: &dyn ProgramLocation) -> Address {
        let source_base = location
            .get_program()
            .get_image_base()
            .expect("rebase_from_canonical requires the source program to have an image base");
        let offset = location.get_byte_address().subtract(&source_base);
        let this_base = self
            .get_program()
            .get_image_base()
            .expect("rebase_from_canonical requires this program to have an image base");
        this_base.add(offset).expect("rebase_from_canonical: address overflow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::RwLock;

    /// A tiny in-memory [`Memory`] over a single flat byte array starting at offset 0, just
    /// enough to exercise [`ProgramByteSource`].
    struct MockMemory {
        data: RwLock<Vec<u8>>,
        program: Arc<dyn Program>,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.offset() as usize;
            self.data
                .read()
                .unwrap()
                .get(offset)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let data = self.data.read().unwrap();
            let start = addr.offset() as usize;
            if start >= data.len() {
                return 0;
            }
            let n = dest.len().min(data.len() - start);
            dest[..n].copy_from_slice(&data[start..start + n]);
            n
        }
        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let start = addr.offset() as usize;
            let mut data = self.data.write().unwrap();
            if start + source.len() > data.len() {
                data.resize(start + source.len(), 0);
            }
            data[start..start + source.len()].copy_from_slice(source);
            Ok(())
        }
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            Some(self.program.clone())
        }
    }

    struct MockProgram {
        factory: Arc<dyn AddressFactory>,
        image_base: Address,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
        fn get_image_base(&self) -> Option<Address> {
            Some(self.image_base.clone())
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    /// A [`Program`] that also knows the [`Memory`] backing it, so `get_memory()` can hand it
    /// back -- `MockProgram` alone can't do this, since the memory itself needs a handle back to
    /// its owning program (mirroring `Memory.getProgram()`).
    struct ProgramWithMemory {
        inner: Arc<dyn Program>,
        memory: Arc<dyn Memory>,
    }
    impl DomainObject for ProgramWithMemory {}
    impl Program for ProgramWithMemory {
        fn get_name(&self) -> String {
            Program::get_name(&*self.inner)
        }
        fn get_language_id(&self) -> String {
            self.inner.get_language_id()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            self.inner.get_address_factory()
        }
        fn get_image_base(&self) -> Option<Address> {
            self.inner.get_image_base()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn program_and_source(data: Vec<u8>) -> (Arc<dyn Program>, ProgramByteSource) {
        let factory: Arc<dyn AddressFactory> = Arc::new(DefaultAddressFactory::new(vec![ram_space()]));
        let program: Arc<dyn Program> = Arc::new(MockProgram { factory, image_base: addr(0x1000) });
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { data: RwLock::new(data), program: program.clone() });
        let full_program: Arc<dyn Program> = Arc::new(ProgramWithMemory { inner: program, memory });
        let source = ProgramByteSource::new(full_program.clone());
        (full_program, source)
    }

    #[test]
    fn get_bytes_reads_from_memory() {
        let (_program, source) = program_and_source(vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut buf = vec![0u8; 10];
        let n = source.get_bytes(&addr(1), &mut buf, 3);
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &[0x02, 0x03, 0x04]);
    }

    #[test]
    fn get_bytes_clamps_to_the_smaller_of_length_and_buffer_size() {
        let (_program, source) = program_and_source(vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        let mut buf = vec![0u8; 2];
        let n = source.get_bytes(&addr(0), &mut buf, 5);
        assert_eq!(n, 2);
    }

    #[test]
    fn get_bytes_out_of_range_returns_zero_instead_of_erroring() {
        let (_program, source) = program_and_source(vec![0x01, 0x02]);
        let mut buf = vec![0u8; 5];
        let n = source.get_bytes(&addr(1000), &mut buf, 5);
        assert_eq!(n, 0);
    }

    #[test]
    fn get_searchable_regions_returns_loaded_and_other() {
        let (_program, source) = program_and_source(vec![]);
        let regions = source.get_searchable_regions();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].get_name(), "Loaded Blocks");
        assert_eq!(regions[1].get_name(), "All Other Blocks");
    }

    #[test]
    fn invalidate_is_callable_and_does_nothing_observable() {
        let (_program, mut source) = program_and_source(vec![1, 2, 3]);
        source.invalidate();
        let mut buf = vec![0u8; 3];
        assert_eq!(source.get_bytes(&addr(0), &mut buf, 3), 3);
    }

    #[test]
    fn get_canonical_location_carries_the_address_and_program() {
        let (_program, source) = program_and_source(vec![1, 2, 3]);
        let location = source.get_canonical_location(&addr(2));
        assert_eq!(location.get_address(), addr(2));
        assert_eq!(location.get_byte_address(), addr(2));
    }

    #[test]
    fn rebase_from_canonical_round_trips_through_image_base() {
        let (_program, source) = program_and_source(vec![1, 2, 3, 4, 5, 6]);
        // Same program on both ends: rebasing a canonical location should be a no-op.
        let location = source.get_canonical_location(&addr(3));
        let rebased = source.rebase_from_canonical(location.as_ref());
        assert_eq!(rebased, addr(3));
    }
}
