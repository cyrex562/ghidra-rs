//! Port of `ghidra.app.util.bin.format.elf.relocation.PIC30_ElfRelocationContext`.
//!
//! Provides PIC30-specific relocation context with special handling for debug sections.
//!
//! # Shape
//!
//! Java's `PIC30_ElfRelocationContext` is a concrete leaf: it extends
//! `ElfRelocationContext<PIC30_ElfRelocationHandler>` with a private method for debug section
//! detection and an override of `getRelocationAddress` to shift offsets for debug sections.
//! Per the port's shape rules a concrete leaf class becomes a `struct` + `impl`, never a trait.

use std::collections::HashMap;
use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::elf::relocation::elf_relocation_context::{
    ElfRelocationContext, ElfRelocationContextBase,
};
use crate::format::seam_stubs::ElfRelocationHandler;
use crate::program::model::address::Address;

/// Provides PIC30-specific relocation context with debug section handling.
///
/// The PIC30 processor requires special handling for relocation offsets when processing
/// debug sections. Debug sections may use different addressing modes where the offset
/// must be shifted right by one bit.
pub struct Pic30ElfRelocationContext {
    base: ElfRelocationContextBase,
}

impl Pic30ElfRelocationContext {
    /// Creates a new PIC30 relocation context.
    ///
    /// # Arguments
    /// * `handler` - PIC30 relocation handler, or `None` if not available
    /// * `load_helper` - the ELF load helper
    /// * `symbol_map` - ELF symbol placement map
    pub fn new(
        handler: Option<Arc<dyn ElfRelocationHandler>>,
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    ) -> Self {
        Pic30ElfRelocationContext {
            base: ElfRelocationContextBase::new(handler, load_helper, symbol_map),
        }
    }

    /// Determines if an address space represents a debug section.
    ///
    /// Debug sections have special handling for relocation offsets on PIC30.
    /// A space is considered a debug section if its name starts with ".debug_" or is ".comment".
    fn is_debug_section(&self, address_space_name: &str) -> bool {
        address_space_name.starts_with(".debug_") || address_space_name == ".comment"
    }
}

impl ElfRelocationContext for Pic30ElfRelocationContext {
    fn base(&self) -> &ElfRelocationContextBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ElfRelocationContextBase {
        &mut self.base
    }

    fn as_relocation_context(&self) -> &dyn ElfRelocationContext {
        self
    }

    /// Get the relocation address for `reloc_offset` relative to `base_address`.
    ///
    /// For PIC30, if the base address is not a loaded memory address and the address space
    /// is a debug section, the relocation offset is shifted right by one bit before applying.
    /// This accounts for PIC30's special addressing mode for debug sections.
    fn get_relocation_address(&self, base_address: &Address, reloc_offset: i64) -> Address {
        let offset = if !base_address.is_loaded_memory_address()
            && self.is_debug_section(&base_address.space().name())
        {
            reloc_offset >> 1
        } else {
            reloc_offset
        };
        base_address.add_wrap(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::{ElfHeader, MessageLog, Throwable};
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::Mutex;
    use std::sync::Arc;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "PIC30:LE:16:default".to_string()
        }
    }

    #[derive(Default)]
    struct RecordingLog {
        messages: Mutex<Vec<String>>,
    }

    impl MessageLog for RecordingLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn append_exception(&self, _t: &dyn Throwable) {}
        fn error(&self, _originator: &str, _message: &str) {}
        fn has_messages(&self) -> bool {
            !self.messages.lock().unwrap().is_empty()
        }
        fn clear(&self) {
            self.messages.lock().unwrap().clear();
        }
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            self.messages.lock().unwrap().join("\n")
        }
        fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, _message_header: &str) {}
    }

    struct MockElfHeader;
    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            false
        }
        fn is_relocatable(&self) -> bool {
            true
        }
        fn get_sections(&self) -> Vec<Box<dyn crate::format::seam_stubs::ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockLoadHelper {
        log: Arc<RecordingLog>,
    }

    impl ElfLoadHelper for MockLoadHelper {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_option_bool(&self, _option_name: &str, default_value: bool) -> bool {
            default_value
        }
        fn get_option_string(
            &self,
            _option_name: &str,
            default_value: Option<String>,
        ) -> Option<String> {
            default_value
        }
        fn get_option_i32(&self, _option_name: &str, default_value: i32) -> i32 {
            default_value
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            Arc::new(MockElfHeader)
        }
        fn get_log(&self) -> Arc<dyn MessageLog> {
            self.log.clone()
        }
        fn log(&self, _msg: &str) {}
        fn log_exception(&self, _t: &dyn std::error::Error) {}
        fn mark_as_code(&self, _address: Address) {}
        fn create_one_byte_function(
            &self,
            _name: Option<&str>,
            _address: Address,
            _is_entry: bool,
        ) -> Arc<dyn crate::program::model::listing::function::Function> {
            unimplemented!("not exercised by these tests")
        }
        fn create_external_function_linkage(
            &self,
            _name: &str,
            _function_addr: Address,
            _indirect_pointer_addr: Option<Address>,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_undefined_data(
            &self,
            _address: Address,
            _length: i32,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_data(
            &self,
            _address: Address,
            _dt: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_elf_symbol_address(&self, _elf_symbol: &ElfSymbol, _address: Option<Address>) {}
        fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> Option<Address> {
            None
        }
        fn create_symbol(
            &self,
            _addr: Address,
            _name: &str,
            _is_primary: bool,
            _pin_absolute: bool,
            _namespace: Option<Arc<dyn crate::program::model::symbol::namespace::Namespace>>,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::Symbol>,
            crate::util::exception::InvalidInputException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn find_load_address(
            &self,
            _section: &dyn crate::format::memory_loadable::MemoryLoadable,
            _byte_offset_within_section: i64,
        ) -> Option<Address> {
            None
        }
        fn get_default_address(&self, _addressable_word_offset: i64) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_image_base_word_adjustment_offset(&self) -> i64 {
            0
        }
        fn get_got_value(&self) -> Option<i64> {
            None
        }
        fn allocate_linkage_block(
            &self,
            _alignment: i32,
            _size: i32,
            _purpose: &str,
        ) -> Option<crate::program::model::address::range::AddressRange> {
            None
        }
        fn get_original_value(
            &self,
            _addr: Address,
            _sign_extend: bool,
        ) -> Result<i64, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
            false
        }
    }

    fn create_context() -> Pic30ElfRelocationContext {
        let load_helper = Arc::new(MockLoadHelper {
            log: Arc::new(RecordingLog::default()),
        });
        Pic30ElfRelocationContext::new(None, load_helper, Arc::new(HashMap::new()))
    }

    #[test]
    fn is_debug_section_recognizes_debug_prefix() {
        let context = create_context();
        assert!(context.is_debug_section(".debug_info"));
        assert!(context.is_debug_section(".debug_line"));
        assert!(context.is_debug_section(".debug_"));
    }

    #[test]
    fn is_debug_section_recognizes_comment_section() {
        let context = create_context();
        assert!(context.is_debug_section(".comment"));
    }

    #[test]
    fn is_debug_section_rejects_non_debug_sections() {
        let context = create_context();
        assert!(!context.is_debug_section(".text"));
        assert!(!context.is_debug_section(".data"));
        assert!(!context.is_debug_section(".symtab"));
        assert!(!context.is_debug_section("debug_info"));
    }

    #[test]
    fn get_relocation_address_without_debug_section_offset() {
        let context = create_context();
        let space = crate::program::model::address::AddressSpace::new(
            "RAM",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let base = Address::new(space, 0x1000);
        let result = context.get_relocation_address(&base, 0x100);

        assert_eq!(result.offset(), 0x1100);
    }

    #[test]
    fn get_relocation_address_shifts_offset_for_debug_section() {
        let context = create_context();
        let space = crate::program::model::address::AddressSpace::new(
            ".debug_info",
            32,
            1,
            AddressSpaceType::Other,
            1,
        );
        let base = Address::new(space, 0x1000);
        let result = context.get_relocation_address(&base, 0x100);

        assert_eq!(result.offset(), 0x1080);
    }

    #[test]
    fn get_relocation_address_does_not_shift_for_loaded_memory_debug_section() {
        let context = create_context();
        let space = crate::program::model::address::AddressSpace::new(
            ".debug_info",
            32,
            1,
            AddressSpaceType::Ram,
            0,
        );
        let base = Address::new(space, 0x1000);
        let result = context.get_relocation_address(&base, 0x100);

        assert_eq!(result.offset(), 0x1100);
    }

    #[test]
    fn new_wires_the_base_context() {
        struct MockHandler;
        impl ElfRelocationHandler for MockHandler {
            fn relocate(
                &self,
                _context: &dyn ElfRelocationContext,
                _relocation: &dyn crate::format::seam_stubs::ElfRelocation,
                _relocation_address: &Address,
            ) -> Result<
                crate::program::model::reloc::RelocationResult,
                crate::format::elf::relocation::elf_relocation_context::RelocationProcessingError,
            > {
                unimplemented!("not exercised by this test")
            }
            fn mark_as_error(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
            fn mark_as_warning(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
        }

        let load_helper = Arc::new(MockLoadHelper {
            log: Arc::new(RecordingLog::default()),
        });
        let context = Pic30ElfRelocationContext::new(
            Some(Arc::new(MockHandler)),
            load_helper,
            Arc::new(HashMap::new()),
        );
        assert!(context.base().has_relocation_handler());
    }
}
