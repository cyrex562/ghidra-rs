use std::sync::Arc;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::dwarf::sectionprovider::dwarf_section_provider::DWARFSectionProvider;
use crate::format::seam_stubs::MemoryByteProvider;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::MemoryBlock;
use crate::util::task::TaskMonitor;

/// Mirrors `ghidra.app.util.bin.format.dwarf.sectionprovider.BaseSectionProvider`.
///
/// Fetches DWARF sections from a normal program using simple Ghidra memory blocks.
pub struct BaseSectionProvider {
    pub program: Arc<dyn Program>,
    /// Prefixes tried (in order) in front of a section name when an exact-name block lookup
    /// misses. `protected` in Java so a subclass can override `getSectionPrefixSearchList()`;
    /// exposed as a field here so a subclass struct embedding this one can set its own list.
    pub section_prefixes: Vec<String>,
}

impl BaseSectionProvider {
    /// Mirrors `BaseSectionProvider.createSectionProviderFor(Program, TaskMonitor)`.
    pub fn create_section_provider_for(
        program: Arc<dyn Program>,
        _monitor: &dyn TaskMonitor,
    ) -> Self {
        BaseSectionProvider::new(program)
    }

    /// Mirrors `new BaseSectionProvider(Program)`.
    pub fn new(program: Arc<dyn Program>) -> Self {
        let section_prefixes = Self::default_section_prefix_search_list();
        BaseSectionProvider { program, section_prefixes }
    }

    /// Mirrors `BaseSectionProvider.getSectionPrefixSearchList()`.
    pub fn default_section_prefix_search_list() -> Vec<String> {
        vec![".".to_string(), "_".to_string(), "__".to_string()]
    }

    /// Mirrors `BaseSectionProvider.getSection(String)`.
    pub fn get_section(&self, section_name: &str) -> Option<Arc<dyn MemoryBlock>> {
        let memory = self.program.get_memory()?;
        if let Some(block) = memory.get_block_by_name(section_name) {
            return Some(block);
        }
        for prefix in &self.section_prefixes {
            if let Some(block) = memory.get_block_by_name(&format!("{prefix}{section_name}")) {
                return Some(block);
            }
        }
        None
    }
}

impl DWARFSectionProvider for BaseSectionProvider {
    fn has_section(&self, section_names: &[&str]) -> bool {
        section_names
            .iter()
            .all(|section_name| self.get_section(section_name).is_some())
    }

    fn get_section_as_byte_provider(
        &self,
        section_name: &str,
        _monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Box<dyn ByteProvider>> {
        match self.get_section(section_name) {
            Some(block) if block.is_initialized() => {
                // NOTE: MemoryByteProvider instances don't need to be closed(), so we don't
                // track them here.
                let memory = self.program.get_memory().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "program has no memory")
                })?;
                Ok(Box::new(MemoryByteProvider::create_memory_block_byte_provider(
                    memory,
                    block.as_ref(),
                )))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("section '{section_name}' not found"),
            )),
        }
    }

    fn close(&mut self) -> std::io::Result<()> {
        // nothing
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlockType};

    struct MockMemoryBlock {
        name: String,
        start: Address,
        size: u64,
        initialized: bool,
    }

    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_start(&self) -> Address {
            self.start.clone()
        }

        fn get_end(&self) -> Address {
            self.start.add(self.size as i64 - 1).unwrap()
        }

        fn get_size(&self) -> u64 {
            self.size
        }

        fn is_initialized(&self) -> bool {
            self.initialized
        }

        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0xAB)
        }

        fn get_bytes(&self, _addr: &Address, dest: &mut [u8]) -> usize {
            dest.fill(0xAB);
            dest.len()
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn get_type(&self) -> MemoryBlockType {
            MemoryBlockType::Default
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
            Ok(0)
        }

        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn get_block_by_name(&self, name: &str) -> Option<Arc<dyn MemoryBlock>> {
            self.blocks
                .iter()
                .find(|block| block.get_name() == name)
                .cloned()
        }
    }

    struct MockProgram {
        memory: Arc<dyn Memory>,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn make_program(blocks: Vec<Arc<dyn MemoryBlock>>) -> Arc<dyn Program> {
        Arc::new(MockProgram {
            memory: Arc::new(MockMemory { blocks }),
        })
    }

    #[test]
    fn default_section_prefix_search_list_matches_java() {
        assert_eq!(
            BaseSectionProvider::default_section_prefix_search_list(),
            vec![".".to_string(), "_".to_string(), "__".to_string()]
        );
    }

    #[test]
    fn get_section_finds_exact_name() {
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock {
            name: "debug_info".to_string(),
            start: test_address(0),
            size: 16,
            initialized: true,
        });
        let provider = BaseSectionProvider::new(make_program(vec![block]));

        assert!(provider.get_section("debug_info").is_some());
    }

    #[test]
    fn get_section_falls_back_to_prefixed_name() {
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock {
            name: ".debug_info".to_string(),
            start: test_address(0),
            size: 16,
            initialized: true,
        });
        let provider = BaseSectionProvider::new(make_program(vec![block]));

        assert!(provider.get_section("debug_info").is_some());
    }

    #[test]
    fn get_section_returns_none_when_missing() {
        let provider = BaseSectionProvider::new(make_program(vec![]));

        assert!(provider.get_section("debug_info").is_none());
    }

    #[test]
    fn has_section_requires_all_names_present() {
        let blocks: Vec<Arc<dyn MemoryBlock>> = vec![
            Arc::new(MockMemoryBlock {
                name: "debug_info".to_string(),
                start: test_address(0),
                size: 16,
                initialized: true,
            }),
            Arc::new(MockMemoryBlock {
                name: "debug_abbrev".to_string(),
                start: test_address(16),
                size: 16,
                initialized: true,
            }),
        ];
        let provider = BaseSectionProvider::new(make_program(blocks));

        assert!(provider.has_section(&["debug_info", "debug_abbrev"]));
        assert!(!provider.has_section(&["debug_info", "debug_line"]));
    }

    #[test]
    fn get_section_as_byte_provider_returns_data_for_initialized_block() {
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock {
            name: "debug_info".to_string(),
            start: test_address(0),
            size: 16,
            initialized: true,
        });
        let provider = BaseSectionProvider::new(make_program(vec![block]));
        let monitor = crate::util::task::DummyMonitor;

        let mut byte_provider = provider
            .get_section_as_byte_provider("debug_info", &monitor)
            .expect("should return provider");
        assert_eq!(byte_provider.length().unwrap(), 16);
    }

    #[test]
    fn get_section_as_byte_provider_errors_for_uninitialized_block() {
        let block: Arc<dyn MemoryBlock> = Arc::new(MockMemoryBlock {
            name: "debug_info".to_string(),
            start: test_address(0),
            size: 16,
            initialized: false,
        });
        let provider = BaseSectionProvider::new(make_program(vec![block]));
        let monitor = crate::util::task::DummyMonitor;

        assert!(provider
            .get_section_as_byte_provider("debug_info", &monitor)
            .is_err());
    }

    #[test]
    fn close_is_a_no_op() {
        let mut provider = BaseSectionProvider::new(make_program(vec![]));
        assert!(provider.close().is_ok());
    }
}
