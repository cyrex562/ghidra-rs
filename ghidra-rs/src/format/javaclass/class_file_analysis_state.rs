//! Holds the parsed [`ClassFileJava`] and per-address [`MethodInfoJava`] lookup for a particular
//! .class file `Program`.
//!
//! Ported from `ghidra.javaclass.format.ClassFileAnalysisState`.
//!
//! These are parsed directly from the .class file (and so can't really change) and are shared
//! with any plug-in that needs to do p-code analysis.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::seam_stubs::{
    ClassFileJava, JavaClassUtil, MemoryByteProvider, MethodInfoJava, TransientPropertyScope,
    TransientProgramProperties,
};
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryAccessException;
use crate::util::msg::Msg;

/// A minimal [`BinaryReader`] backed by a [`ByteProvider`].
///
/// The crate does not yet have a canonical production implementer of the [`BinaryReader`] trait,
/// so this mirrors the `ByteProvider`-backed constructor of the original `BinaryReader.java`
/// class, consistent with the identical local helper in
/// [`elf_info_item`](crate::format::elf::info::elf_info_item).
struct ProviderBinaryReader {
    provider: Rc<RefCell<dyn ByteProvider>>,
    is_little_endian: bool,
    current_index: u64,
}

impl ProviderBinaryReader {
    fn new(provider: Rc<RefCell<dyn ByteProvider>>, is_little_endian: bool) -> Self {
        ProviderBinaryReader { provider, is_little_endian, current_index: 0 }
    }
}

impl BinaryReader for ProviderBinaryReader {
    fn length(&self) -> io::Result<u64> {
        self.provider.borrow_mut().length()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        self.provider.borrow_mut().is_valid_index(index)
    }

    fn get_pointer_index(&self) -> u64 {
        self.current_index
    }

    fn set_pointer_index(&mut self, index: u64) -> u64 {
        let previous = self.current_index;
        self.current_index = index;
        previous
    }

    fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.is_little_endian = is_little_endian;
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.borrow_mut().read_byte(index)
    }

    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        self.provider.borrow_mut().read_bytes(index, n_elements)
    }

    fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::clone(&self.provider)
    }

    fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
        Box::new(ProviderBinaryReader {
            provider: Rc::clone(&self.provider),
            is_little_endian: self.is_little_endian,
            current_index: new_index,
        })
    }
}

/// Class for holding the [`ClassFileJava`] and [`MethodInfoJava`] in memory for a particular
/// .class file `Program`. These describe the objects in the constant pool and signatures of
/// individual methods.
///
/// Port of `ghidra.javaclass.format.ClassFileAnalysisState`.
pub struct ClassFileAnalysisState {
    program: Arc<dyn Program>,
    class_file: ClassFileJava,
    /// Map from address to method description. Mirrors the Java field's lazy-build-once
    /// semantics (`if (methodMap == null) { buildMethodMap(); }`) with interior mutability,
    /// since `get_method_info` is called through a shared `Arc<ClassFileAnalysisState>`.
    method_map: Mutex<Option<HashMap<Address, MethodInfoJava>>>,
}

impl ClassFileAnalysisState {
    /// Mirrors `ClassFileAnalysisState(Program)`.
    pub fn new(program: Arc<dyn Program>) -> io::Result<Self> {
        let factory = program
            .get_address_factory()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Not a valid class file"))?;
        let space = factory
            .get_address_space_by_name("constantPool")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Not a valid class file"))?;
        let memory = program
            .get_memory()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Not a valid class file"))?;

        let provider = MemoryByteProvider::new(memory, &space);
        let mut reader = ProviderBinaryReader::new(Rc::new(RefCell::new(provider)), false);
        let class_file = ClassFileJava::new(&mut reader)?;

        Ok(ClassFileAnalysisState { program, class_file, method_map: Mutex::new(None) })
    }

    /// The class file information. Mirrors `ClassFileAnalysisState.getClassFile()`.
    pub fn get_class_file(&self) -> &ClassFileJava {
        &self.class_file
    }

    /// Recover the description of the method at a specific address, or `None` if no method is
    /// found at the address. Mirrors `ClassFileAnalysisState.getMethodInfo(Address)`.
    pub fn get_method_info(&self, addr: &Address) -> Option<MethodInfoJava> {
        let mut guard = self.method_map.lock().unwrap();
        if guard.is_none() {
            match self.build_method_map() {
                Ok(map) => *guard = Some(map),
                Err(e) => {
                    Msg::error_with_error("ClassFileAnalysisState", &e.to_string(), &e);
                    // methodMap will be non-null but empty
                    *guard = Some(HashMap::new());
                }
            }
        }
        guard.as_ref().and_then(|map| map.get(addr).copied())
    }

    /// Walk through the [`MethodInfoJava`] objects in [`ClassFileJava`] and build a map from
    /// address to the corresponding object. Mirrors `ClassFileAnalysisState.buildMethodMap()`.
    fn build_method_map(&self) -> Result<HashMap<Address, MethodInfoJava>, MemoryAccessException> {
        let mut method_map = HashMap::new();
        let methods = self.class_file.get_methods();
        let memory = self
            .program
            .get_memory()
            .ok_or_else(|| MemoryAccessException::new("program has no memory"))?;
        let default_address_space = self
            .program
            .get_address_factory()
            .and_then(|factory| factory.get_default_address_space())
            .ok_or_else(|| MemoryAccessException::new("program has no default address space"))?;

        for (i, method) in methods.iter().enumerate() {
            let method_index_address =
                JavaClassUtil::to_lookup_address(self.program.as_ref(), i as i32);

            let mut buf = [0u8; 4];
            let n_read = memory.get_bytes(&method_index_address, &mut buf);
            if n_read != buf.len() {
                return Err(MemoryAccessException::new(format!(
                    "Unable to read int at {method_index_address}"
                )));
            }
            let offset =
                if memory.is_big_endian() { i32::from_be_bytes(buf) } else { i32::from_le_bytes(buf) };
            let method_start = default_address_space.address(offset as i64);
            method_map.insert(method_start, *method);
        }

        Ok(method_map)
    }

    /// Return the persistent [`ClassFileAnalysisState`] which corresponds to the specified
    /// program instance. Mirrors `ClassFileAnalysisState.getState(Program)`.
    pub fn get_state(program: Arc<dyn Program>) -> io::Result<Arc<ClassFileAnalysisState>> {
        TransientProgramProperties::get_property(&program, TransientPropertyScope::Program, || {
            ClassFileAnalysisState::new(program.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::ClassFileJava;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::mem::{Memory, MemoryBlock};

    struct FakeMemoryBlock {
        name: String,
        start: Address,
        data: Vec<u8>,
    }

    impl MemoryBlock for FakeMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_start(&self) -> Address {
            self.start.clone()
        }

        fn get_end(&self) -> Address {
            self.start.add((self.data.len() as i64 - 1).max(0)).unwrap()
        }

        fn get_size(&self) -> u64 {
            self.data.len() as u64
        }

        fn is_initialized(&self) -> bool {
            true
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.subtract(&self.start) as usize;
            self.data.get(offset).copied().ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.subtract(&self.start);
            if offset < 0 {
                return 0;
            }
            let offset = offset as usize;
            let available = self.data.len().saturating_sub(offset);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[offset..offset + n]);
            n
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }
    }

    struct FakeMemory {
        constant_pool_block: Option<Arc<dyn MemoryBlock>>,
        lookup_bytes: HashMap<i64, [u8; 4]>,
        default_space: Arc<AddressSpace>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let mut buf = [0u8; 1];
            if self.get_bytes(addr, &mut buf) == 1 { Ok(buf[0]) } else { Err(MemoryAccessException::new("no data")) }
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            if addr.space() == &self.default_space {
                if let Some(bytes) = self.lookup_bytes.get(&addr.offset()) {
                    let n = dest.len().min(4);
                    dest[..n].copy_from_slice(&bytes[..n]);
                    return n;
                }
                return 0;
            }
            if let Some(block) = &self.constant_pool_block {
                if block.contains(addr) {
                    return block.get_bytes(addr, dest);
                }
            }
            0
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }

        fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
            self.constant_pool_block.iter().cloned().collect()
        }
    }

    struct FakeProgram {
        factory: Arc<dyn crate::program::model::address::AddressFactory>,
        memory: Arc<FakeMemory>,
    }

    impl crate::framework::model::DomainObject for FakeProgram {}

    impl Program for FakeProgram {
        fn get_name(&self) -> String {
            "class_file_analysis_state_test".to_string()
        }

        fn get_language_id(&self) -> String {
            "JVM:BE:32:default".to_string()
        }

        fn get_address_factory(&self) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            Some(self.factory.clone())
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn constant_pool_space() -> Arc<AddressSpace> {
        AddressSpace::new("constantPool", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn default_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn program_without_constant_pool_space() -> Arc<dyn Program> {
        let default_space = default_space();
        let factory: Arc<dyn crate::program::model::address::AddressFactory> =
            Arc::new(DefaultAddressFactory::new(vec![default_space.clone()]));
        let memory = Arc::new(FakeMemory {
            constant_pool_block: None,
            lookup_bytes: HashMap::new(),
            default_space,
        });
        Arc::new(FakeProgram { factory, memory })
    }

    fn program_with_class_file() -> Arc<dyn Program> {
        let constant_pool_space = constant_pool_space();
        let default_space = default_space();
        let cp_start = Address::new(constant_pool_space.clone(), 0);
        let factory: Arc<dyn crate::program::model::address::AddressFactory> =
            Arc::new(DefaultAddressFactory::with_default_space(
                vec![default_space.clone(), constant_pool_space.clone()],
                Some(default_space.clone()),
            ));
        let block: Arc<dyn MemoryBlock> = Arc::new(FakeMemoryBlock {
            name: "constantPool".to_string(),
            start: cp_start,
            data: vec![0xCA, 0xFE, 0xBA, 0xBE],
        });
        let memory = Arc::new(FakeMemory {
            constant_pool_block: Some(block),
            lookup_bytes: HashMap::new(),
            default_space,
        });
        Arc::new(FakeProgram { factory, memory })
    }

    /// `ClassFileAnalysisState(Program)` throws `IllegalStateException("Not a valid class
    /// file")` when the program has no `constantPool` address space.
    #[test]
    fn new_fails_without_constant_pool_address_space() {
        let program = program_without_constant_pool_space();
        match ClassFileAnalysisState::new(program) {
            Ok(_) => panic!("expected an error for a program with no constantPool space"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
        }
    }

    /// `ClassFileAnalysisState(Program)` succeeds when a `constantPool` address space and memory
    /// are present, and `getMethodInfo` returns `null` (`None`) for a class file with no methods.
    #[test]
    fn get_method_info_returns_none_when_no_methods_present() {
        let program = program_with_class_file();
        let state = ClassFileAnalysisState::new(program.clone()).expect("valid class file");

        let addr = Address::new(default_space(), 0x1000);
        assert!(state.get_method_info(&addr).is_none());
        // Second call exercises the "already built" branch of the lazy cache.
        assert!(state.get_method_info(&addr).is_none());
    }

    /// `buildMethodMap` reads a 4-byte lookup table entry per method (at
    /// `JavaClassUtil.toLookupAddress(program, i)`) and uses it as an offset into the default
    /// address space to key the method map.
    #[test]
    fn build_method_map_keys_methods_by_lookup_table_offset() {
        let constant_pool_space = constant_pool_space();
        let default_space = default_space();
        let cp_start = Address::new(constant_pool_space.clone(), 0);
        let factory: Arc<dyn crate::program::model::address::AddressFactory> =
            Arc::new(DefaultAddressFactory::with_default_space(
                vec![default_space.clone(), constant_pool_space.clone()],
                Some(default_space.clone()),
            ));
        let block: Arc<dyn MemoryBlock> = Arc::new(FakeMemoryBlock {
            name: "constantPool".to_string(),
            start: cp_start,
            data: vec![0xCA, 0xFE, 0xBA, 0xBE],
        });

        let lookup_address_0 = JavaClassUtil::LOOKUP_ADDRESS;
        let lookup_address_1 = JavaClassUtil::LOOKUP_ADDRESS + 4;
        let mut lookup_bytes = HashMap::new();
        lookup_bytes.insert(lookup_address_0, 0x0000_2000i32.to_be_bytes());
        lookup_bytes.insert(lookup_address_1, 0x0000_3000i32.to_be_bytes());

        let memory = Arc::new(FakeMemory {
            constant_pool_block: Some(block),
            lookup_bytes,
            default_space: default_space.clone(),
        });
        let program: Arc<dyn Program> = Arc::new(FakeProgram { factory, memory });

        let mut state = ClassFileAnalysisState::new(program).expect("valid class file");
        state.class_file =
            ClassFileJava::from_methods(vec![MethodInfoJava::new(10), MethodInfoJava::new(20)]);

        let addr0 = Address::new(default_space.clone(), 0x2000);
        let addr1 = Address::new(default_space.clone(), 0x3000);

        assert_eq!(state.get_method_info(&addr0).map(|m| m.get_offset()), Some(10));
        assert_eq!(state.get_method_info(&addr1).map(|m| m.get_offset()), Some(20));
        assert!(state.get_method_info(&Address::new(default_space, 0x9999)).is_none());
    }

    /// `JavaClassUtil.toLookupAddress` computes `LOOKUP_ADDRESS + methodIndex * 4` in the
    /// program's default address space.
    #[test]
    fn to_lookup_address_matches_java_formula() {
        let program = program_with_class_file();
        let addr = JavaClassUtil::to_lookup_address(program.as_ref(), 2);
        assert_eq!(addr.offset(), JavaClassUtil::LOOKUP_ADDRESS.wrapping_add(8));
        assert_eq!(addr.space().name(), "ram");
    }

    /// `ClassFileAnalysisState.getState(Program)` is documented as returning a "shared/persistent"
    /// instance: repeated calls for the same program return the same object rather than
    /// reconstructing it.
    #[test]
    fn get_state_caches_the_instance_per_program() {
        let program = program_with_class_file();
        let first = ClassFileAnalysisState::get_state(program.clone()).expect("first call");
        let second = ClassFileAnalysisState::get_state(program).expect("second call");
        assert!(Arc::ptr_eq(&first, &second));
    }
}
