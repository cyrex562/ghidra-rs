//! Port of `ghidra.app.util.sourcelanguage.ElfSwiftSourceLanguage`.

use crate::app::util::opinion::elf_loader::ELF_NAME;
use crate::app::util::sourcelanguage::source_language::{ExistsInError, SourceLanguage};
use crate::app::util::sourcelanguage::source_language_id::SourceLanguageId;
use crate::app::util::sourcelanguage::swift_source_language::{
    SwiftSourceLanguage, SwiftSourceLanguageBase,
};
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

/// The Elf Swift [`SourceLanguage`].
///
/// Port of `ghidra.app.util.sourcelanguage.ElfSwiftSourceLanguage`, which `extends
/// SwiftSourceLanguage`. Per this crate's composition-over-inheritance convention, and matching
/// [`SwiftSourceLanguage`]'s own established base/trait-shadowing pattern (see its module docs and
/// [`SwiftSourceLanguageBase`]'s docs for why), this wraps a [`SwiftSourceLanguageBase`] marker
/// and implements both [`SourceLanguage`] (supplying a real `exists_in`) and
/// [`SwiftSourceLanguage`] (whose default `get_id` this type's own `SourceLanguage::get_id`
/// forwards to, so every Swift-flavored `SourceLanguage` reports the same shared `SWIFT_ID`).
/// This is this crate's first real (non-test) implementor of that shadowing pattern.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ElfSwiftSourceLanguage {
    _base: SwiftSourceLanguageBase,
}

impl ElfSwiftSourceLanguage {
    /// Constructs a new `ElfSwiftSourceLanguage`. There being no state to carry (see
    /// [`SwiftSourceLanguageBase`]'s own docs), this is equivalent to `Self::default()`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SourceLanguage for ElfSwiftSourceLanguage {
    fn get_id(&self) -> Box<dyn SourceLanguageId> {
        SwiftSourceLanguage::get_id(self)
    }

    /// Port of `ElfSwiftSourceLanguage.existsIn(Program, TaskMonitor)`.
    ///
    /// Java: `if (!program.getExecutableFormat().equals(ElfLoader.ELF_NAME)) { return false; }
    /// return Arrays.stream(program.getMemory().getBlocks()).map(MemoryBlock::getName)
    /// .anyMatch(name -> name.startsWith("swift"));`. Java implicitly requires `program.getMemory()`
    /// to be non-null (it is unconditionally dereferenced); this port additionally treats a
    /// program with no memory available (`get_memory()` returning `None`, a possibility this
    /// port's [`Program`] trait allows that Java's non-null `Memory` reference does not) the same
    /// as "no blocks", i.e. `false`, rather than panicking.
    fn exists_in(
        &self,
        program: &dyn Program,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, ExistsInError> {
        if program.get_executable_format() != ELF_NAME {
            return Ok(false);
        }
        let Some(memory) = program.get_memory() else {
            return Ok(false);
        };
        Ok(memory.get_blocks().iter().any(|block| block.get_name().starts_with("swift")))
    }
}

impl SwiftSourceLanguage for ElfSwiftSourceLanguage {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
    use std::sync::Arc;

    struct MockMemoryBlock {
        name: String,
    }
    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_start(&self) -> Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
        fn get_end(&self) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_size(&self) -> u64 {
            0
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Err(MemoryAccessException::new("not exercised by these tests"))
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("not exercised by these tests"))
        }
    }

    struct MockMemory {
        blocks: Vec<Arc<dyn MemoryBlock>>,
    }
    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Err(MemoryAccessException::new("not exercised by these tests"))
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("not exercised by these tests"))
        }
        fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
            self.blocks.clone()
        }
    }

    struct MockProgram {
        executable_format: String,
        memory: Option<Arc<dyn Memory>>,
    }
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
        fn get_executable_format(&self) -> String {
            self.executable_format.clone()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            self.memory.clone()
        }
    }

    fn elf_program(block_names: &[&str]) -> MockProgram {
        let blocks: Vec<Arc<dyn MemoryBlock>> = block_names
            .iter()
            .map(|name| Arc::new(MockMemoryBlock { name: name.to_string() }) as Arc<dyn MemoryBlock>)
            .collect();
        MockProgram {
            executable_format: ELF_NAME.to_string(),
            memory: Some(Arc::new(MockMemory { blocks })),
        }
    }

    #[test]
    fn exists_in_is_false_for_a_non_elf_program() {
        let language = ElfSwiftSourceLanguage::new();
        let program = MockProgram { executable_format: "PE".to_string(), memory: None };
        let monitor = crate::util::task::DummyMonitor;

        assert_eq!(language.exists_in(&program, &monitor).unwrap(), false);
    }

    #[test]
    fn exists_in_is_false_when_elf_has_no_swift_prefixed_blocks() {
        let language = ElfSwiftSourceLanguage::new();
        let program = elf_program(&[".text", ".data"]);
        let monitor = crate::util::task::DummyMonitor;

        assert_eq!(language.exists_in(&program, &monitor).unwrap(), false);
    }

    #[test]
    fn exists_in_is_true_when_elf_has_a_swift_prefixed_block() {
        let language = ElfSwiftSourceLanguage::new();
        let program = elf_program(&[".text", "swift5_types", ".data"]);
        let monitor = crate::util::task::DummyMonitor;

        assert_eq!(language.exists_in(&program, &monitor).unwrap(), true);
    }

    #[test]
    fn exists_in_is_false_when_elf_program_has_no_memory() {
        let language = ElfSwiftSourceLanguage::new();
        let program = MockProgram { executable_format: ELF_NAME.to_string(), memory: None };
        let monitor = crate::util::task::DummyMonitor;

        assert_eq!(language.exists_in(&program, &monitor).unwrap(), false);
    }

    #[test]
    fn get_id_is_the_shared_swift_id() {
        let language = ElfSwiftSourceLanguage::new();
        assert_eq!(SourceLanguage::get_id(&language).get_id_as_string(), "Swift");
    }

    #[test]
    fn usable_as_source_language_trait_object() {
        let language: Box<dyn SourceLanguage> = Box::new(ElfSwiftSourceLanguage::new());
        assert_eq!(language.get_id().get_id_as_string(), "Swift");
    }
}
