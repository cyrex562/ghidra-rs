//! Port of `ghidra.app.util.bin.format.elf.relocation.X86_64_ElfRelocationContext`.
//!
//! Provides the ability to generate a Global Offset Table (GOT) to facilitate GOT-related
//! relocations encountered within object modules.
//!
//! # Shape
//!
//! Java's `X86_64_ElfRelocationContext` is a tiny concrete leaf: it extends
//! `ElfGotRelocationContext<X86_64_ElfRelocationHandler>` with nothing but a constructor and an
//! override of the single abstract method `requiresGotEntry`. Per the port's shape rules a
//! concrete leaf class becomes a `struct` + `impl`, never a trait.
//!
//! # Departures from the Java class
//!
//! * `ElfGotRelocationContext` (the immediate superclass) is not ported yet -- see
//!   `ElfGotRelocationContext.java`, tracked separately in `PORT_MANIFEST.tsv`. This is the
//!   dependency cycle the recursive-descent order warned about (the handler that eventually
//!   constructs this context is itself unported). Rather than guess at
//!   `ElfGotRelocationContext`'s unported GOT-allocation state, this port composes directly over
//!   [`ElfRelocationContextBase`] (the already-ported grandparent) and implements
//!   [`ElfRelocationContext`] on it, exactly like a direct `ElfRelocationContext` subclass would
//!   (mirrors [`crate::format::elf::relocation::aarch64_elf_relocation_context::Aarch64ElfRelocationContext`]).
//!   The GOT-specific overrides (`getSymbolValue`, `getGOTValue`, `dispose`) stay unported along
//!   with `ElfGotRelocationContext` itself; only [`requires_got_entry`](Self::requires_got_entry)
//!   -- the method this Java class actually defines -- is ported here.
//! * The constructor's `X86_64_ElfRelocationHandler handler` parameter is narrowed in Java only so
//!   `requiresGotEntry` can call the handler's inherited `getRelocationType`. This port avoids
//!   that dependency entirely: because relocation type IDs are unique per architecture, "does
//!   `r.getType()` resolve to one of the GOT relocation types" is equivalent to "does
//!   `r.getType()` equal one of those types' `typeId`", so no handler lookup is needed.
//!   [`new`](Self::new) therefore accepts the already-ported general
//!   [`ElfRelocationHandler`] trait, matching [`ElfRelocationContextBase::new`], instead of a
//!   stub for the unported `X86_64_ElfRelocationHandler`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::elf::relocation::elf_relocation_context::{
    ElfRelocationContext, ElfRelocationContextBase,
};
use crate::format::elf::relocation::x86_64_elf_relocation_type::X86_64ElfRelocationType;
use crate::format::seam_stubs::{ElfRelocation, ElfRelocationHandler};
use crate::program::model::address::Address;

/// Relocation types which require a GOT allocation.
///
/// NOTE: Relocation may not actually require a GOT entry in which case `%got` may be
/// over-allocated, but it is required in some cases. Matches the `switch` in Java's
/// `requiresGotEntry`.
const GOT_ENTRY_RELOCATION_TYPES: [X86_64ElfRelocationType; 4] = [
    X86_64ElfRelocationType::R_X86_64_GOTPCREL,
    X86_64ElfRelocationType::R_X86_64_GOTPCREL64,
    X86_64ElfRelocationType::R_X86_64_GOTPCRELX,
    X86_64ElfRelocationType::R_X86_64_REX_GOTPCRELX,
];

/// Provides the ability to generate a Global Offset Table (GOT) to facilitate GOT related
/// relocations encountered within x86-64 object modules.
pub struct X86_64ElfRelocationContext {
    base: ElfRelocationContextBase,
}

impl X86_64ElfRelocationContext {
    /// Relocation context for a specific x86-64 ELF image and relocation table.
    ///
    /// # Arguments
    /// * `handler` - x86-64 relocation handler, or `None` if not available
    /// * `load_helper` - the ELF load helper
    /// * `symbol_map` - ELF symbol placement map
    pub fn new(
        handler: Option<Arc<dyn ElfRelocationHandler>>,
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    ) -> Self {
        X86_64ElfRelocationContext {
            base: ElfRelocationContextBase::new(handler, load_helper, symbol_map),
        }
    }

    /// Returns true if the specified relocation type requires a GOT entry.
    pub fn requires_got_entry(&self, r: &dyn ElfRelocation) -> bool {
        let type_id = r.get_type();
        GOT_ENTRY_RELOCATION_TYPES
            .iter()
            .any(|got_type| got_type.type_id_value() == type_id)
    }
}

impl ElfRelocationContext for X86_64ElfRelocationContext {
    fn base(&self) -> &ElfRelocationContextBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ElfRelocationContextBase {
        &mut self.base
    }

    fn as_relocation_context(&self) -> &dyn ElfRelocationContext {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::{ElfHeader, MessageLog, Throwable};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::Mutex;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
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

    struct MockRelocation {
        type_id: i32,
    }

    impl ElfRelocation for MockRelocation {
        fn get_symbol_index(&self) -> i32 {
            0
        }
        fn get_type(&self) -> i32 {
            self.type_id
        }
    }

    fn context() -> X86_64ElfRelocationContext {
        let load_helper = Arc::new(MockLoadHelper { log: Arc::new(RecordingLog::default()) });
        X86_64ElfRelocationContext::new(None, load_helper, Arc::new(HashMap::new()))
    }

    #[test]
    fn requires_got_entry_matches_the_four_java_cases() {
        let context = context();

        // case R_X86_64_GOTPCREL:
        assert!(context.requires_got_entry(&MockRelocation { type_id: 9 }));
        // case R_X86_64_GOTPCREL64:
        assert!(context.requires_got_entry(&MockRelocation { type_id: 28 }));
        // case R_X86_64_GOTPCRELX:
        assert!(context.requires_got_entry(&MockRelocation { type_id: 41 }));
        // case R_X86_64_REX_GOTPCRELX:
        assert!(context.requires_got_entry(&MockRelocation { type_id: 42 }));
    }

    #[test]
    fn requires_got_entry_is_false_for_other_known_and_unknown_types() {
        let context = context();

        // A resolvable type that isn't in the GOT list (R_X86_64_64).
        assert!(!context.requires_got_entry(&MockRelocation { type_id: 1 }));
        // The commented-out Java cases (R_X86_64_GOTOFF64, R_X86_64_GOTPC32, R_X86_64_GOT64,
        // R_X86_64_GOTPC64) must NOT require a GOT entry.
        assert!(!context.requires_got_entry(&MockRelocation { type_id: 25 }));
        assert!(!context.requires_got_entry(&MockRelocation { type_id: 26 }));
        assert!(!context.requires_got_entry(&MockRelocation { type_id: 27 }));
        assert!(!context.requires_got_entry(&MockRelocation { type_id: 29 }));
        // An unresolvable type id.
        assert!(!context.requires_got_entry(&MockRelocation { type_id: 99_999 }));
    }

    #[test]
    fn new_wires_the_handler_into_the_base_context() {
        struct NoopHandler;
        impl ElfRelocationHandler for NoopHandler {
            fn relocate(
                &self,
                _context: &dyn ElfRelocationContext,
                _relocation: &dyn ElfRelocation,
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

        let load_helper = Arc::new(MockLoadHelper { log: Arc::new(RecordingLog::default()) });
        let context = X86_64ElfRelocationContext::new(
            Some(Arc::new(NoopHandler)),
            load_helper,
            Arc::new(HashMap::new()),
        );

        assert!(context.base().has_relocation_handler());
    }
}
