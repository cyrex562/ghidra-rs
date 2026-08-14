//! Port of `ghidra.app.util.bin.format.elf.relocation.AbstractElfRelocationHandler`.
//!
//! # Shape
//!
//! Java's `AbstractElfRelocationHandler<T extends ElfRelocationType, C extends
//! ElfRelocationContext<?>>` is a concrete class -- carrying the `relocationTypesMap` field and
//! every concrete markup method -- that ~20 architecture-specific handlers extend, each supplying
//! only the abstract `relocate` fixup. Rust splits the two:
//!
//! * [`AbstractElfRelocationHandlerBase`] owns the field and every concrete method.
//! * [`AbstractElfRelocationHandler`] declares only the abstract `relocate` fixup; a port of one
//!   of the concrete handlers holds an `AbstractElfRelocationHandlerBase`, implements this trait,
//!   and drives [`AbstractElfRelocationHandlerBase::relocate`] as the `ElfRelocationHandler`
//!   implementation Java gets for free via inheritance.
//!
//! # Departures from the Java class
//!
//! * Java's `C extends ElfRelocationContext<?>` type parameter exists only so a subclass can read
//!   its own specialized context without a cast. [`ElfRelocationContext`] is already ported as a
//!   single trait covering every context (see its module docs), so this port takes `&dyn
//!   ElfRelocationContext` throughout instead of threading a second generic parameter.
//! * `Class<T> relocationEnumClass` plus reflection over `getEnumConstants()` has no Rust
//!   equivalent; [`AbstractElfRelocationHandlerBase::new`] takes the enum's values directly.
//! * `ElfSymbolNameUtils.replaceInvalidChars` and the `ElfRelocationHandler` static markup
//!   helpers (`getDefaultRelocationTypeDetail`, `markupErrorOrWarning`) are unported dependencies
//!   this class inherits/calls; see the `elf_relocation_handler` and `elf_symbol_name_utils`
//!   seam stubs. `markupErrorOrWarning`'s bookmark half is a no-op until `BookmarkManager` lands
//!   (only the import-log message is realized).
//! * `getSymbol(symbolIndex)` is documented "will never be null" in Java; the port asserts that
//!   invariant with `expect` rather than threading an unreachable `Option` through the signature.
//! * [`AbstractElfRelocationHandlerBase::handle_unresolved_symbol`] avoids a latent Java NPE: if
//!   `getRelocationType` cannot resolve `typeId` (only possible if a caller invokes this method
//!   before the dispatcher in [`AbstractElfRelocationHandlerBase::relocate`] has validated it),
//!   Java's `markAsUnhandled`/`markAsError` overloads dereference a null `relocationType`. The
//!   port falls back to [`elf_relocation_handler::get_default_relocation_type_detail`] instead.

use std::collections::HashMap;

use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext;
use crate::format::elf::relocation::elf_relocation_type::ElfRelocationType;
use crate::format::memory_loadable::MemoryLoadable;
use crate::format::seam_stubs::{elf_relocation_handler, elf_symbol_name_utils, ElfRelocation, MessageLog};
use crate::program::model::address::Address;
use crate::program::model::listing::bookmark_type;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::reloc::RelocationResult;

/// The shared state of an ELF relocation handler, plus every method Java does not mark
/// `abstract`.
///
/// See the [module documentation](self) for why the state and the abstract behaviour are split.
pub struct AbstractElfRelocationHandlerBase<T: ElfRelocationType + Copy> {
    relocation_types_map: HashMap<i32, T>,
}

impl<T: ElfRelocationType + Copy> AbstractElfRelocationHandlerBase<T> {
    /// Builds the relocation type lookup table from every value of the handler's
    /// [`ElfRelocationType`] enum.
    ///
    /// Stands in for Java's `initRelocationTypeMap`, which populates the map by reflecting over
    /// `relocationEnumClass.getEnumConstants()`.
    pub fn new(relocation_types: impl IntoIterator<Item = T>) -> Self {
        let mut relocation_types_map = HashMap::new();
        for relocation_type in relocation_types {
            relocation_types_map.insert(relocation_type.type_id(), relocation_type);
        }
        AbstractElfRelocationHandlerBase { relocation_types_map }
    }

    /// Get the relocation type enum value which corresponds to the specified type ID value, or
    /// `None` if not found.
    pub fn get_relocation_type(&self, type_id: i32) -> Option<T> {
        self.relocation_types_map.get(&type_id).copied()
    }

    /// `AbstractElfRelocationHandler.getRelocationTypeDetail(T)`.
    fn relocation_type_detail(relocation_type: T) -> String {
        let type_id = relocation_type.type_id();
        format!("{} ({type_id}, 0x{type_id:x})", relocation_type.name())
    }

    /// Perform relocation fixup.
    ///
    /// Ports Java's `final relocate(ElfRelocationContext, ElfRelocation, Address)`: resolves the
    /// symbol and relocation type, handles the type-0/unresolved-type shortcuts, and otherwise
    /// defers to `handler`'s abstract [`AbstractElfRelocationHandler::relocate`].
    pub fn relocate<H>(
        &self,
        handler: &H,
        elf_relocation_context: &dyn ElfRelocationContext,
        relocation: &dyn ElfRelocation,
        relocation_address: &Address,
    ) -> Result<RelocationResult, MemoryAccessException>
    where
        H: AbstractElfRelocationHandler<T> + ?Sized,
    {
        let base = elf_relocation_context.base();
        let symbol_index = relocation.get_symbol_index();

        let sym = base
            .get_symbol(symbol_index)
            .expect("ElfRelocationContext.getSymbol never returns null for a valid index");
        let symbol_addr = elf_relocation_context.get_symbol_address(&sym);
        let symbol_value = elf_relocation_context.get_symbol_value(&sym);
        let symbol_name = base
            .get_symbol_name(symbol_index)
            .map(|name| elf_symbol_name_utils::replace_invalid_chars(&name));

        let type_id = relocation.get_type();
        if type_id == 0 {
            return Ok(RelocationResult::SKIPPED);
        }

        let Some(relocation_type) = self.get_relocation_type(type_id) else {
            self.mark_as_undefined(
                base.get_program().as_ref(),
                relocation_address,
                type_id,
                symbol_name.as_deref(),
                symbol_index,
                base.get_log().as_ref(),
            );
            return Ok(RelocationResult::UNSUPPORTED);
        };

        handler.relocate(
            elf_relocation_context,
            relocation,
            relocation_type,
            relocation_address,
            &sym,
            symbol_addr.as_ref(),
            symbol_value,
            symbol_name.as_deref(),
        )
    }

    /// Check for an unresolved relocation symbol. If the symbol has not been resolved, the
    /// associated symbol address will be `None` and the symbol value invalid.
    ///
    /// Returns `true` if the symbol was not resolved (and marks the relocation as an unhandled
    /// error), else `false` if the symbol was resolved.
    pub fn handle_unresolved_symbol(
        &self,
        elf_relocation_context: &dyn ElfRelocationContext,
        relocation: &dyn ElfRelocation,
        relocation_address: &Address,
    ) -> bool {
        let base = elf_relocation_context.base();
        let symbol_index = relocation.get_symbol_index();

        let sym = base.get_symbol(symbol_index);
        let symbol_addr =
            sym.as_ref().and_then(|sym| elf_relocation_context.get_symbol_address(sym));

        if symbol_index == 0 || symbol_addr.is_some() {
            return false;
        }

        let type_id = relocation.get_type();
        let detail = self
            .get_relocation_type(type_id)
            .map(Self::relocation_type_detail)
            .unwrap_or_else(|| elf_relocation_handler::get_default_relocation_type_detail(type_id));

        let symbol_name = base
            .get_symbol_name(symbol_index)
            .map(|name| elf_symbol_name_utils::replace_invalid_chars(&name));
        let program = base.get_program();
        let log = base.get_log();

        elf_relocation_handler::markup_error_or_warning(
            program.as_ref(),
            "Unhandled ELF Relocation",
            None,
            relocation_address,
            &detail,
            symbol_index,
            symbol_name.as_deref(),
            bookmark_type::ERROR,
            Some(log.as_ref()),
        );
        elf_relocation_handler::markup_error_or_warning(
            program.as_ref(),
            "Elf Relocation Failure",
            Some("Failed to resolve relocation symbol"),
            relocation_address,
            &detail,
            symbol_index,
            symbol_name.as_deref(),
            bookmark_type::ERROR,
            Some(log.as_ref()),
        );
        true
    }

    /// Generate error log entry and bookmark at `relocation_address` indicating an unsupportable
    /// COPY relocation. A warning is produced for this COPY relocation failure.
    #[allow(clippy::too_many_arguments)]
    pub fn mark_as_unsupported_copy(
        &self,
        program: &dyn Program,
        relocation_address: &Address,
        relocation_type: T,
        symbol_name: Option<&str>,
        symbol_index: i32,
        symbol_size: i64,
        log: &dyn MessageLog,
    ) {
        self.mark_as_warning(
            program,
            relocation_address,
            relocation_type,
            symbol_name,
            symbol_index,
            &format!("Runtime copy not supported ({symbol_size}-bytes)"),
            log,
        );
    }

    /// Generate error log entry and bookmark at `relocation_address` indicating an unhandled
    /// relocation whose type ID could not be resolved to an [`ElfRelocationType`] value.
    pub fn mark_as_undefined(
        &self,
        program: &dyn Program,
        relocation_address: &Address,
        type_id: i32,
        symbol_name: Option<&str>,
        symbol_index: i32,
        log: &dyn MessageLog,
    ) {
        elf_relocation_handler::markup_error_or_warning(
            program,
            "Undefined ELF Relocation",
            None,
            relocation_address,
            &elf_relocation_handler::get_default_relocation_type_detail(type_id),
            symbol_index,
            symbol_name,
            bookmark_type::ERROR,
            Some(log),
        );
    }

    /// Generate error log entry and bookmark at `relocation_address` indicating an unhandled
    /// relocation.
    pub fn mark_as_unhandled(
        &self,
        program: &dyn Program,
        relocation_address: &Address,
        relocation_type: T,
        symbol_index: i32,
        symbol_name: Option<&str>,
        log: &dyn MessageLog,
    ) {
        elf_relocation_handler::markup_error_or_warning(
            program,
            "Unhandled ELF Relocation",
            None,
            relocation_address,
            &Self::relocation_type_detail(relocation_type),
            symbol_index,
            symbol_name,
            bookmark_type::ERROR,
            Some(log),
        );
    }

    /// Generate relocation warning log entry and bookmark at `relocation_address`.
    #[allow(clippy::too_many_arguments)]
    pub fn mark_as_warning(
        &self,
        program: &dyn Program,
        relocation_address: &Address,
        relocation_type: T,
        symbol_name: Option<&str>,
        symbol_index: i32,
        msg: &str,
        log: &dyn MessageLog,
    ) {
        elf_relocation_handler::markup_error_or_warning(
            program,
            "ELF Relocation Failure",
            Some(msg),
            relocation_address,
            &Self::relocation_type_detail(relocation_type),
            symbol_index,
            symbol_name,
            bookmark_type::WARNING,
            Some(log),
        );
    }

    /// Generate relocation error log entry and bookmark at `relocation_address`.
    #[allow(clippy::too_many_arguments)]
    pub fn mark_as_error(
        &self,
        program: &dyn Program,
        relocation_address: &Address,
        relocation_type: T,
        symbol_name: Option<&str>,
        symbol_index: i32,
        msg: &str,
        log: &dyn MessageLog,
    ) {
        elf_relocation_handler::markup_error_or_warning(
            program,
            "Elf Relocation Failure",
            Some(msg),
            relocation_address,
            &Self::relocation_type_detail(relocation_type),
            symbol_index,
            symbol_name,
            bookmark_type::ERROR,
            Some(log),
        );
    }
}

/// The abstract behaviour of an ELF relocation handler: the architecture-specific fixup a
/// concrete handler must supply.
///
/// Ports Java's `protected abstract RelocationResult relocate(C, ElfRelocation, T, Address,
/// ElfSymbol, Address, long, String)`. Not invoked when `elfSymbol` is `null` (checked by
/// [`ElfRelocationContext::process_relocation`]) or when the relocation type is `0`/`NONE`
/// (checked by [`AbstractElfRelocationHandlerBase::relocate`], which marks those as skipped).
pub trait AbstractElfRelocationHandler<T: ElfRelocationType + Copy> {
    /// Perform relocation fixup.
    #[allow(clippy::too_many_arguments)]
    fn relocate(
        &self,
        elf_relocation_context: &dyn ElfRelocationContext,
        relocation: &dyn ElfRelocation,
        relocation_type: T,
        relocation_address: &Address,
        elf_symbol: &ElfSymbol,
        symbol_addr: Option<&Address>,
        symbol_value: i64,
        symbol_name: Option<&str>,
    ) -> Result<RelocationResult, MemoryAccessException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::format::elf::elf_load_helper::ElfLoadHelper;
    use crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase;
    use crate::format::seam_stubs::{Class, ElfHeader, ElfSectionHeader, Throwable};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::reloc::RelocationStatus;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DummyRelocationType {
        None,
        Abs32,
        Copy,
    }

    impl ElfRelocationType for DummyRelocationType {
        fn name(&self) -> &str {
            match self {
                DummyRelocationType::None => "R_DUMMY_NONE",
                DummyRelocationType::Abs32 => "R_DUMMY_ABS32",
                DummyRelocationType::Copy => "R_DUMMY_COPY",
            }
        }

        fn type_id(&self) -> i32 {
            match self {
                DummyRelocationType::None => 0,
                DummyRelocationType::Abs32 => 2,
                DummyRelocationType::Copy => 5,
            }
        }
    }

    const ALL_TYPES: [DummyRelocationType; 3] =
        [DummyRelocationType::None, DummyRelocationType::Abs32, DummyRelocationType::Copy];

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
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
        fn write(&self, _owner: &dyn Class, _message_header: &str) {}
    }

    struct MockElfHeader;
    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            true
        }
        fn is_relocatable(&self) -> bool {
            false
        }
        fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>> {
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
            _section: &dyn MemoryLoadable,
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
        ) -> Result<i64, crate::program::model::mem::memory_access_exception::MemoryAccessException>
        {
            unimplemented!("not exercised by these tests")
        }
        fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
            false
        }
    }

    struct MockRelocation {
        symbol_index: i32,
        type_id: i32,
    }

    impl ElfRelocation for MockRelocation {
        fn get_symbol_index(&self) -> i32 {
            self.symbol_index
        }
        fn get_type(&self) -> i32 {
            self.type_id
        }
    }

    /// A relocation table with no associated symbol table, so that index 0 resolves to the
    /// context's null symbol (see `ElfRelocationContext::start_relocation_table_processing`).
    struct MockRelocationTable;

    impl crate::format::seam_stubs::ElfRelocationTable for MockRelocationTable {
        fn has_addend_relocations(&self) -> bool {
            false
        }
        fn get_associated_symbol_table(
            &self,
        ) -> Option<Arc<dyn crate::format::seam_stubs::ElfSymbolTable>> {
            None
        }
    }

    /// Records the arguments the abstract `relocate` fixup was invoked with.
    struct RecordingHandler {
        calls: Mutex<Vec<(i32, i64, i64, Option<String>)>>,
    }

    impl AbstractElfRelocationHandler<DummyRelocationType> for RecordingHandler {
        fn relocate(
            &self,
            _elf_relocation_context: &dyn ElfRelocationContext,
            _relocation: &dyn ElfRelocation,
            relocation_type: DummyRelocationType,
            _relocation_address: &Address,
            _elf_symbol: &ElfSymbol,
            symbol_addr: Option<&Address>,
            symbol_value: i64,
            symbol_name: Option<&str>,
        ) -> Result<RelocationResult, MemoryAccessException> {
            self.calls.lock().unwrap().push((
                relocation_type.type_id(),
                symbol_addr.map_or(-1i64, Address::offset),
                symbol_value,
                symbol_name.map(str::to_string),
            ));
            Ok(RelocationResult::new(RelocationStatus::Applied, 4))
        }
    }

    fn address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn context() -> (ElfRelocationContextBase, Arc<RecordingLog>) {
        let log = Arc::new(RecordingLog::default());
        let load_helper = Arc::new(MockLoadHelper { log: log.clone() });
        let mut context = ElfRelocationContextBase::new(None, load_helper, Arc::new(HashMap::new()));
        context.start_relocation_table_processing(Arc::new(MockRelocationTable));
        (context, log)
    }

    // ---------------------------------------------------------------- get_relocation_type

    #[test]
    fn relocation_type_map_is_built_from_type_id() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        assert_eq!(base.get_relocation_type(2), Some(DummyRelocationType::Abs32));
        assert_eq!(base.get_relocation_type(5), Some(DummyRelocationType::Copy));
        assert_eq!(base.get_relocation_type(99), None);
    }

    // ---------------------------------------------------------------- relocate dispatcher

    #[test]
    fn relocate_skips_type_zero_without_invoking_the_handler() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let handler = RecordingHandler { calls: Mutex::new(Vec::new()) };
        let (context, _log) = context();

        let result = base.relocate(
            &handler,
            &context,
            &MockRelocation { symbol_index: 0, type_id: 0 },
            &address(0x1000),
        );

        assert_eq!(result.unwrap(), RelocationResult::SKIPPED);
        assert!(handler.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn relocate_marks_undefined_types_as_unsupported() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let handler = RecordingHandler { calls: Mutex::new(Vec::new()) };
        let (context, log) = context();

        let result = base.relocate(
            &handler,
            &context,
            &MockRelocation { symbol_index: 0, type_id: 42 },
            &address(0x1000),
        );

        assert_eq!(result.unwrap(), RelocationResult::UNSUPPORTED);
        assert!(handler.calls.lock().unwrap().is_empty());
        let messages = log.messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Undefined ELF Relocation"), "got {:?}", messages[0]);
        assert!(messages[0].contains("Type = 42 (0x2a)"), "got {:?}", messages[0]);
    }

    #[test]
    fn relocate_dispatches_a_known_type_to_the_handler() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let handler = RecordingHandler { calls: Mutex::new(Vec::new()) };
        let (context, _log) = context();

        let result = base.relocate(
            &handler,
            &context,
            &MockRelocation { symbol_index: 0, type_id: 2 },
            &address(0x2000),
        );

        assert_eq!(result.unwrap(), RelocationResult::new(RelocationStatus::Applied, 4));
        let calls = handler.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (type_id, symbol_addr_offset, symbol_value, symbol_name) = &calls[0];
        assert_eq!(*type_id, 2);
        // No symbol table: index 0 resolves to the null symbol, which has no placement.
        assert_eq!(*symbol_addr_offset, -1);
        assert_eq!(*symbol_value, 0);
        assert_eq!(symbol_name.as_deref(), None);
    }

    // ---------------------------------------------------------------- handle_unresolved_symbol

    #[test]
    fn handle_unresolved_symbol_is_false_for_the_null_symbol() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let (context, log) = context();

        // Index 0 always resolves to the null symbol, which handleUnresolvedSymbol special-cases.
        let unresolved = base.handle_unresolved_symbol(
            &context,
            &MockRelocation { symbol_index: 0, type_id: 2 },
            &address(0x1000),
        );

        assert!(!unresolved);
        assert!(log.messages.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_unresolved_symbol_marks_two_bookmarks_when_unresolved() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let (context, log) = context();

        // No symbol table: any non-zero index is out of range, i.e. unresolved.
        let unresolved = base.handle_unresolved_symbol(
            &context,
            &MockRelocation { symbol_index: 7, type_id: 5 },
            &address(0x3000),
        );

        assert!(unresolved);
        let messages = log.messages.lock().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("Unhandled ELF Relocation"), "got {:?}", messages[0]);
        assert!(messages[0].contains("R_DUMMY_COPY (5, 0x5)"), "got {:?}", messages[0]);
        assert!(messages[1].contains("Elf Relocation Failure"), "got {:?}", messages[1]);
        assert!(messages[1].contains("Failed to resolve relocation symbol"), "got {:?}", messages[1]);
    }

    // ---------------------------------------------------------------- markup formatting

    #[test]
    fn mark_as_error_matches_java_markup_format() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let log = RecordingLog::default();

        base.mark_as_error(
            &MockProgram,
            &address(0x1000),
            DummyRelocationType::Copy,
            Some("foo"),
            3,
            "bad offset",
            &log,
        );

        assert_eq!(
            log.messages.lock().unwrap().as_slice(),
            ["Elf Relocation Failure: R_DUMMY_COPY (5, 0x5) at ram:0x1000 \
              (Symbol = foo) - bad offset"
                .to_string()]
        );
    }

    #[test]
    fn mark_as_error_falls_back_to_the_no_name_placeholder() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let log = RecordingLog::default();

        base.mark_as_error(
            &MockProgram,
            &address(0x1000),
            DummyRelocationType::Copy,
            None,
            -1,
            "bad offset",
            &log,
        );

        assert!(log.messages.lock().unwrap()[0].contains("Symbol = <no name>"));
    }

    #[test]
    fn mark_as_unsupported_copy_reports_the_byte_count() {
        let base = AbstractElfRelocationHandlerBase::new(ALL_TYPES);
        let log = RecordingLog::default();

        base.mark_as_unsupported_copy(
            &MockProgram,
            &address(0x1000),
            DummyRelocationType::Copy,
            Some("g_value"),
            1,
            8,
            &log,
        );

        let messages = log.messages.lock().unwrap();
        assert!(messages[0].contains("Runtime copy not supported (8-bytes)"), "got {:?}", messages[0]);
    }
}
