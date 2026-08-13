//! Port of `ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext`.
//!
//! The relocation context carries the state a relocation handler needs while it walks one ELF
//! relocation table: the handler itself, the load helper, the symbol placement map, and the table
//! (plus its associated symbol table) currently being processed.
//!
//! # Shape
//!
//! Java's `ElfRelocationContext` is a *concrete* class that six architecture-specific classes
//! extend, so it carries both state and overridable behaviour. Rust splits the two:
//!
//! * [`ElfRelocationContextBase`] owns the fields and every `final` method (the ones Java forbids
//!   subclasses from touching).
//! * [`ElfRelocationContext`] declares the overridable methods, each with a default body that
//!   delegates to the base -- exactly the behaviour Java's own class supplies. A subclass port
//!   holds an `ElfRelocationContextBase`, returns it from [`ElfRelocationContext::base`], and
//!   overrides only the methods it actually specializes.
//!
//! `ElfRelocationContextBase` itself implements `ElfRelocationContext`; that combination is the
//! "generic context" Java falls back to in `getRelocationContext` when no handler defines a custom
//! one.
//!
//! # Departures from the Java class
//!
//! * Java's type parameter `<H extends ElfRelocationHandler>` exists only so subclasses can name
//!   their handler at its precise type. The handler is chosen at run time by
//!   `ElfRelocationHandlerFactory` from the ELF machine, so the port stores
//!   `Option<Arc<dyn ElfRelocationHandler>>`; `Option` models the nullable Java field.
//! * `getRelocationContext` consulted the (unported) `ElfRelocationHandlerFactory`. The port takes
//!   the already-resolved handler as a parameter instead of stubbing a handler registry that does
//!   not exist yet -- see [`ElfRelocationContextBase::get_relocation_context`].
//! * [`ElfRelocationContext::dispose`] cannot yet do its work; see its documentation.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::seam_stubs::{
    elf_relocation_handler, ElfHeader, ElfLoadAdapter, ElfLoadHelper, ElfRelocation,
    ElfRelocationHandler, ElfRelocationTable, ElfSymbolTable, MessageLog,
};
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::reloc::RelocationResult;
use crate::util::exception::NotFoundException;

/// The two checked exceptions `ElfRelocationContext.processRelocation` catches together
/// (`MemoryAccessException | NotFoundException`).
///
/// Java's own javadoc notes that `NotFoundException` is deprecated here and should no longer be
/// thrown; it is kept so already-written handlers keep type-checking.
#[derive(Debug)]
pub enum RelocationProcessingError {
    /// A memory access failed while applying the relocation.
    MemoryAccess(MemoryAccessException),
    /// Deprecated: a handler reported a missing dependency (e.g. the GOT) as a failure.
    NotFound(NotFoundException),
}

impl RelocationProcessingError {
    /// The detail text Java reads back with `Throwable.getMessage()`.
    pub fn message(&self) -> &str {
        match self {
            RelocationProcessingError::MemoryAccess(e) => e.message().unwrap_or_default(),
            RelocationProcessingError::NotFound(e) => &e.0,
        }
    }
}

impl fmt::Display for RelocationProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for RelocationProcessingError {}

impl From<MemoryAccessException> for RelocationProcessingError {
    fn from(e: MemoryAccessException) -> Self {
        RelocationProcessingError::MemoryAccess(e)
    }
}

impl From<NotFoundException> for RelocationProcessingError {
    fn from(e: NotFoundException) -> Self {
        RelocationProcessingError::NotFound(e)
    }
}

/// Message Java logs through the load helper when no relocation handler was found for the image.
const NO_HANDLER_MESSAGE: &str = "Unable to process ELF relocations: relocation handler not found";

/// The shared state of an ELF relocation context, plus every method Java declares `final`.
///
/// See the [module documentation](self) for why the state and the overridable behaviour are split.
pub struct ElfRelocationContextBase {
    handler: Option<Arc<dyn ElfRelocationHandler>>,
    load_helper: Arc<dyn ElfLoadHelper>,
    symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    program: Arc<dyn Program>,

    relocation_table: Option<Arc<dyn ElfRelocationTable>>,
    /// May be `None`: not every relocation table has an associated symbol table.
    symbol_table: Option<Arc<dyn ElfSymbolTable>>,

    /// Corresponds to `symbolIndex == 0` when there is no symbol table.
    null_symbol: Option<ElfSymbol>,
}

impl ElfRelocationContextBase {
    /// Relocation context for a specific ELF image and relocation table.
    ///
    /// # Arguments
    /// * `handler` - relocation handler, or `None` if not available
    /// * `load_helper` - the ELF load helper
    /// * `symbol_map` - ELF symbol placement map
    pub fn new(
        handler: Option<Arc<dyn ElfRelocationHandler>>,
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    ) -> Self {
        let program = load_helper.get_program();

        if handler.is_none() {
            load_helper.log(NO_HANDLER_MESSAGE);
        }

        ElfRelocationContextBase {
            handler,
            load_helper,
            symbol_map,
            program,
            relocation_table: None,
            symbol_table: None,
            null_symbol: None,
        }
    }

    /// Get a relocation context for a specific ELF image and relocation table.
    ///
    /// A generic context ([`ElfRelocationContextBase`]) is returned if the handler does not define
    /// a custom one.
    ///
    /// Unlike Java's static `getRelocationContext`, the handler is passed in already resolved
    /// rather than looked up through `ElfRelocationHandlerFactory`, which is not ported yet.
    pub fn get_relocation_context(
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
        handler: Option<Arc<dyn ElfRelocationHandler>>,
    ) -> Box<dyn ElfRelocationContext> {
        let custom = handler
            .as_ref()
            .and_then(|h| h.create_relocation_context(load_helper.clone(), symbol_map.clone()));

        custom.unwrap_or_else(|| {
            Box::new(ElfRelocationContextBase::new(handler, load_helper, symbol_map))
        })
    }

    /// The relocation handler, or `None` if none was found for this image.
    ///
    /// Stands in for Java's `protected final H handler` field, which subclasses read directly.
    pub fn handler(&self) -> Option<&Arc<dyn ElfRelocationHandler>> {
        self.handler.as_ref()
    }

    /// True if a relocation handler was found.
    pub fn has_relocation_handler(&self) -> bool {
        self.handler.is_some()
    }

    /// The relocation table currently being processed, or `None` outside a
    /// [`start`](ElfRelocationContext::start_relocation_table_processing)/[`end`](ElfRelocationContext::end_relocation_table_processing)
    /// window.
    pub fn relocation_table(&self) -> Option<&Arc<dyn ElfRelocationTable>> {
        self.relocation_table.as_ref()
    }

    /// The symbol table associated with the relocation table currently being processed. `None`
    /// when the table has no associated symbol table (or outside a processing window).
    pub fn symbol_table(&self) -> Option<&Arc<dyn ElfSymbolTable>> {
        self.symbol_table.as_ref()
    }

    pub fn get_program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    pub fn is_big_endian(&self) -> bool {
        self.program
            .get_memory()
            .is_some_and(|memory| memory.is_big_endian())
    }

    pub fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
        self.load_helper.get_elf_header()
    }

    pub fn get_load_helper(&self) -> &Arc<dyn ElfLoadHelper> {
        &self.load_helper
    }

    /// The ELF extension adapter for this image.
    ///
    /// Java's `ElfHeader.getLoadAdapter()` never returns null; the unported `ElfHeader` seam has no
    /// adapter registry to fall back on, so this can currently answer `None`.
    pub fn get_load_adapter(&self) -> Option<Arc<dyn ElfLoadAdapter>> {
        self.get_elf_header().get_load_adapter()
    }

    pub fn get_log(&self) -> Arc<dyn MessageLog> {
        self.load_helper.get_log()
    }

    /// Get the ELF symbol which corresponds to the specified index.
    ///
    /// Each relocation table may correspond to a specific symbol table to which `symbol_index` is
    /// applied. In the absence of a corresponding symbol table, index 0 returns a special null
    /// symbol. Returns `None` if the index is out of range.
    pub fn get_symbol(&self, symbol_index: i32) -> Option<ElfSymbol> {
        match &self.symbol_table {
            None => {
                if symbol_index == 0 {
                    self.null_symbol.clone()
                } else {
                    None
                }
            }
            Some(symbol_table) => symbol_table.get_symbol(symbol_index),
        }
    }

    /// Get the ELF symbol name which corresponds to the specified index, or `None` if out of range
    /// (or if there is no associated symbol table).
    pub fn get_symbol_name(&self, symbol_index: i32) -> Option<String> {
        self.symbol_table
            .as_ref()
            .and_then(|symbol_table| symbol_table.get_symbol_name(symbol_index))
    }

    /// Generate a relocation error log entry and bookmark.
    ///
    /// # Arguments
    /// * `relocation_address` - relocation address
    /// * `type_id` - relocation type ID value (mapped to
    ///   [`ElfRelocationType::name`](crate::format::elf::relocation::elf_relocation_type::ElfRelocationType::name)
    ///   if possible)
    /// * `symbol_index` - associated symbol index within the symbol table (-1 to ignore)
    /// * `symbol_name` - relocation symbol name, or `None` if unknown
    /// * `msg` - error message
    pub fn mark_relocation_error(
        &self,
        relocation_address: &Address,
        type_id: i32,
        symbol_index: i32,
        symbol_name: Option<&str>,
        msg: &str,
    ) {
        let log = self.get_log();
        match &self.handler {
            // Note the -1: Java discards the caller's symbolIndex on this branch.
            Some(handler) => handler.mark_as_error(
                self.program.as_ref(),
                relocation_address,
                type_id,
                symbol_name,
                -1,
                msg,
                log.as_ref(),
            ),
            // Must use the static method, which performs no relocation type resolution.
            None => elf_relocation_handler::mark_as_error(
                self.program.as_ref(),
                relocation_address,
                type_id,
                symbol_index,
                symbol_name,
                msg,
                log.as_ref(),
            ),
        }
    }
}

/// The overridable behaviour of an ELF relocation context.
///
/// Every method has a default body reproducing what Java's `ElfRelocationContext` does, so a
/// subclass port only has to supply [`base`](Self::base), [`base_mut`](Self::base_mut) and
/// [`as_relocation_context`](Self::as_relocation_context) and then override what it specializes.
///
/// [`process_relocation`](Self::process_relocation) and the accessors on
/// [`ElfRelocationContextBase`] correspond to Java's `final` members and are not meant to be
/// overridden.
pub trait ElfRelocationContext {
    /// The shared state this context is built on.
    fn base(&self) -> &ElfRelocationContextBase;

    /// Mutable access to the shared state this context is built on.
    fn base_mut(&mut self) -> &mut ElfRelocationContextBase;

    /// Upcast to `&dyn ElfRelocationContext`, which the handler's `relocate` needs. Implementors
    /// write `self`.
    fn as_relocation_context(&self) -> &dyn ElfRelocationContext;

    /// Invoked at the start of relocation processing for the specified table.
    /// [`end_relocation_table_processing`](Self::end_relocation_table_processing) is invoked after
    /// the last relocation is processed.
    fn start_relocation_table_processing(&mut self, reloc_table: Arc<dyn ElfRelocationTable>) {
        let symbol_table = reloc_table.get_associated_symbol_table();
        let base = self.base_mut();
        base.null_symbol = symbol_table.is_none().then(ElfSymbol::new);
        base.symbol_table = symbol_table;
        base.relocation_table = Some(reloc_table);
    }

    /// Invoked at the end of relocation processing for the current relocation table.
    fn end_relocation_table_processing(&mut self) {
        self.base_mut().relocation_table = None;
    }

    /// Process a relocation from the relocation table which corresponds to this context.
    ///
    /// All relocation entries are processed in the order they appear within the table. This
    /// mirrors Java's `final` overload: it resolves the symbol, rejects the cases no handler can
    /// deal with, and then defers to
    /// [`process_relocation_for_symbol`](Self::process_relocation_for_symbol).
    fn process_relocation(
        &self,
        relocation: &dyn ElfRelocation,
        relocation_address: &Address,
    ) -> RelocationResult {
        let base = self.base();
        let symbol_index = relocation.get_symbol_index();
        let sym = base.get_symbol(symbol_index);

        let Some(handler) = base.handler() else {
            let symbol_name = sym.as_ref().and_then(ElfSymbol::get_name_as_string);
            elf_relocation_handler::bookmark_no_handler_error(
                base.get_program().as_ref(),
                relocation_address,
                relocation.get_type(),
                symbol_index,
                symbol_name,
            );
            return RelocationResult::FAILURE;
        };

        let log = base.get_log();

        let Some(sym) = sym else {
            handler.mark_as_error(
                base.get_program().as_ref(),
                relocation_address,
                relocation.get_type(),
                None,
                -1,
                &format!("Invalid symbol index ({symbol_index})"),
                log.as_ref(),
            );
            return RelocationResult::FAILURE;
        };

        if sym.is_tls() {
            handler.mark_as_warning(
                base.get_program().as_ref(),
                relocation_address,
                relocation.get_type(),
                sym.get_name_as_string(),
                symbol_index,
                "Relocation for TLS Symbol not supported",
                log.as_ref(),
            );
            return RelocationResult::UNSUPPORTED;
        }

        match self.process_relocation_for_symbol(relocation, &sym, relocation_address) {
            Ok(result) => result,
            Err(e) => {
                base.get_load_helper().log_exception(&e);
                handler.mark_as_error(
                    base.get_program().as_ref(),
                    relocation_address,
                    relocation.get_type(),
                    sym.get_name_as_string(),
                    symbol_index,
                    &format!("Processing Failure - {}", e.message()),
                    log.as_ref(),
                );
                RelocationResult::FAILURE
            }
        }
    }

    /// Process a relocation after the preliminary checks have been performed and the ELF symbol
    /// has been resolved.
    ///
    /// Ports Java's `protected processRelocation(ElfRelocation, ElfSymbol, Address)`, whose name
    /// collides with the `final` overload above once the parameter lists are erased.
    fn process_relocation_for_symbol(
        &self,
        relocation: &dyn ElfRelocation,
        elf_symbol: &ElfSymbol,
        relocation_address: &Address,
    ) -> Result<RelocationResult, RelocationProcessingError> {
        let _ = elf_symbol;
        match self.base().handler() {
            Some(handler) => handler.relocate(
                self.as_relocation_context(),
                relocation,
                relocation_address,
            ),
            // Unreachable through `process_relocation`, which rejects a missing handler first.
            None => Ok(RelocationResult::FAILURE),
        }
    }

    /// Get the RELR relocation type associated with the underlying relocation handler, or 0 if
    /// RELR is not supported.
    fn get_relr_relocation_type(&self) -> i32 {
        self.base()
            .handler()
            .map_or(0, |handler| handler.get_relr_relocation_type())
    }

    /// Get the image base addressable word adjustment value to be applied to any pre-linked
    /// address values, such as those contained in the dynamic table. (Applies to the default
    /// address space only.)
    fn get_image_base_word_adjustment_offset(&self) -> i64 {
        self.base()
            .get_load_helper()
            .get_image_base_word_adjustment_offset()
    }

    /// Determine if addend data must be extracted, i.e. whether the relocation itself does not
    /// provide the addend and it has to be read back from the relocation target.
    ///
    /// Java dereferences the relocation table unconditionally and so throws if called outside a
    /// table's processing window; with no table in hand the port answers `true`, which is the
    /// answer for every `REL`-style table.
    fn extract_addend(&self) -> bool {
        self.base()
            .relocation_table()
            .is_none_or(|table| !table.has_addend_relocations())
    }

    /// Get the program address at which the specified ELF symbol was placed, or `None` if the
    /// symbol has no placement.
    fn get_symbol_address(&self, symbol: &ElfSymbol) -> Option<Address> {
        self.base().symbol_map.get(symbol).cloned()
    }

    /// Get the adjusted symbol value based upon its placement within the program.
    ///
    /// This value may differ from [`ElfSymbol::get_value`] and reflects the addressable
    /// unit/word offset of the symbol's program address. Returns 0 if no mapping is found.
    fn get_symbol_value(&self, symbol: &ElfSymbol) -> i64 {
        self.get_symbol_address(symbol)
            .map_or(0, |addr| addr.addressable_word_offset())
    }

    /// Returns the appropriate `.got` section address offset, using the `DT_PLTGOT` value defined
    /// in the `.dynamic` section, falling back to the symbol offset for `_GLOBAL_OFFSET_TABLE_`.
    ///
    /// # Errors
    /// [`NotFoundException`] if `DT_PLTGOT` is not defined and the `_GLOBAL_OFFSET_TABLE_` symbol
    /// is not defined either.
    fn get_got_value(&self) -> Result<i64, NotFoundException> {
        self.base()
            .get_load_helper()
            .get_got_value()
            .ok_or_else(|| {
                NotFoundException::with_message("Failed to identify _GLOBAL_OFFSET_TABLE_")
            })
    }

    /// Dispose of the relocation context when processing of the corresponding relocation table is
    /// complete, so all program changes are flushed before a subsequent table is processed.
    ///
    /// **Not yet implemented.** Java reconciles the extended `EXTERNAL.ext` program-tree fragment
    /// back into `EXTERNAL`: it renames the extended fragment when no `EXTERNAL` fragment exists,
    /// and otherwise moves the extended fragment's code units into `EXTERNAL` and removes the
    /// now-empty extended fragment from its parent module. Every step of that needs *mutable*
    /// access to the program tree, and the ported seam offers none: `Program::get_listing` takes
    /// `&mut self` behind an `Arc<dyn Program>`, `Listing::get_fragment_by_name` hands back a
    /// shared `Arc<dyn ProgramFragment>`, and `Group::get_parents` returns owned `Box`es whose
    /// mutation could not reach the real module. The body is left empty rather than faking a
    /// reconciliation; it should be filled in once `ProgramFragment`/`ProgramModule` land.
    fn dispose(&mut self) {}

    /// Get the relocation address for `reloc_offset` relative to `base_address`.
    fn get_relocation_address(&self, base_address: &Address, reloc_offset: i64) -> Address {
        base_address.add_wrap(reloc_offset)
    }
}

impl ElfRelocationContext for ElfRelocationContextBase {
    fn base(&self) -> &ElfRelocationContextBase {
        self
    }

    fn base_mut(&mut self) -> &mut ElfRelocationContextBase {
        self
    }

    fn as_relocation_context(&self) -> &dyn ElfRelocationContext {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Mutex;

    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::elf::elf_section_header_constants::SHN_UNDEF;
    use crate::format::elf::elf_symbol::{STB_GLOBAL, STT_FUNC, STT_TLS};
    use crate::format::seam_stubs::{ElfSectionHeader, Throwable};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::reloc::RelocationStatus;

    // ---------------------------------------------------------------- test doubles

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

    /// Records every message written to it so tests can assert on the markup text.
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
            true
        }
        fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockLoadHelper {
        log: Arc<RecordingLog>,
        /// Messages passed to `ElfLoadHelper.log(...)`, which is distinct from the import log.
        helper_log: Mutex<Vec<String>>,
        image_base_word_adjustment: i64,
        got_value: Option<i64>,
    }

    impl MockLoadHelper {
        fn new() -> Self {
            MockLoadHelper {
                log: Arc::new(RecordingLog::default()),
                helper_log: Mutex::new(Vec::new()),
                image_base_word_adjustment: 0,
                got_value: None,
            }
        }
    }

    impl ElfLoadHelper for MockLoadHelper {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            Arc::new(MockElfHeader)
        }
        fn get_log(&self) -> Arc<dyn MessageLog> {
            self.log.clone()
        }
        fn log(&self, msg: &str) {
            self.helper_log.lock().unwrap().push(msg.to_string());
        }
        fn log_exception(&self, t: &dyn std::error::Error) {
            self.helper_log.lock().unwrap().push(t.to_string());
        }
        fn get_image_base_word_adjustment_offset(&self) -> i64 {
            self.image_base_word_adjustment
        }
        fn get_got_value(&self) -> Option<i64> {
            self.got_value
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

    struct MockSymbolTable {
        symbols: Vec<ElfSymbol>,
    }

    impl ElfSymbolTable for MockSymbolTable {
        fn get_extended_section_index(&self, _sym: &ElfSymbol) -> i32 {
            0
        }
        fn get_symbol(&self, symbol_index: i32) -> Option<ElfSymbol> {
            usize::try_from(symbol_index)
                .ok()
                .and_then(|i| self.symbols.get(i))
                .cloned()
        }
        fn get_symbol_name(&self, symbol_index: i32) -> Option<String> {
            self.get_symbol(symbol_index)
                .and_then(|s| s.get_name_as_string().map(str::to_string))
        }
    }

    struct MockRelocationTable {
        has_addend: bool,
        symbol_table: Option<Arc<dyn ElfSymbolTable>>,
    }

    impl ElfRelocationTable for MockRelocationTable {
        fn has_addend_relocations(&self) -> bool {
            self.has_addend
        }
        fn get_associated_symbol_table(&self) -> Option<Arc<dyn ElfSymbolTable>> {
            self.symbol_table.clone()
        }
    }

    /// What a relocation handler was asked to do, so tests can check the dispatch arguments.
    #[derive(Debug, PartialEq, Eq)]
    enum HandlerCall {
        Error { type_id: i32, symbol_name: Option<String>, symbol_index: i32, msg: String },
        Warning { type_id: i32, symbol_name: Option<String>, symbol_index: i32, msg: String },
        Relocate { symbol_index: i32, type_id: i32 },
    }

    struct MockHandler {
        calls: Mutex<Vec<HandlerCall>>,
        relr_type: i32,
        /// What `relocate` should answer; `None` makes it fail with a memory access error.
        relocate_result: Option<RelocationResult>,
    }

    impl MockHandler {
        fn new() -> Self {
            MockHandler {
                calls: Mutex::new(Vec::new()),
                relr_type: 0,
                relocate_result: Some(RelocationResult::new(RelocationStatus::Applied, 4)),
            }
        }
    }

    impl ElfRelocationHandler for MockHandler {
        fn get_relr_relocation_type(&self) -> i32 {
            self.relr_type
        }
        fn relocate(
            &self,
            context: &dyn ElfRelocationContext,
            relocation: &dyn ElfRelocation,
            _relocation_address: &Address,
        ) -> Result<RelocationResult, RelocationProcessingError> {
            // The context must be usable from inside the handler, as it is in Java.
            assert!(context.base().has_relocation_handler());
            self.calls.lock().unwrap().push(HandlerCall::Relocate {
                symbol_index: relocation.get_symbol_index(),
                type_id: relocation.get_type(),
            });
            self.relocate_result.ok_or_else(|| {
                RelocationProcessingError::MemoryAccess(MemoryAccessException::new(
                    "no memory at address",
                ))
            })
        }
        fn mark_as_error(
            &self,
            _program: &dyn Program,
            _relocation_address: &Address,
            type_id: i32,
            symbol_name: Option<&str>,
            symbol_index: i32,
            msg: &str,
            _log: &dyn MessageLog,
        ) {
            self.calls.lock().unwrap().push(HandlerCall::Error {
                type_id,
                symbol_name: symbol_name.map(str::to_string),
                symbol_index,
                msg: msg.to_string(),
            });
        }
        fn mark_as_warning(
            &self,
            _program: &dyn Program,
            _relocation_address: &Address,
            type_id: i32,
            symbol_name: Option<&str>,
            symbol_index: i32,
            msg: &str,
            _log: &dyn MessageLog,
        ) {
            self.calls.lock().unwrap().push(HandlerCall::Warning {
                type_id,
                symbol_name: symbol_name.map(str::to_string),
                symbol_index,
                msg: msg.to_string(),
            });
        }
    }

    // ---------------------------------------------------------------- fixtures

    fn address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// An `ElfSymbol` of the given binding and type, parsed from a synthetic `Elf32_Sym` entry
    /// (`st_name`, `st_value`, `st_size`, `st_info`, `st_other`, `st_shndx`, little endian).
    fn symbol(bind: u8, sym_type: u8) -> ElfSymbol {
        let st_info = (bind << 4) | (sym_type & 0xf);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // st_name
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // st_value
        bytes.extend_from_slice(&4u32.to_le_bytes()); // st_size
        bytes.push(st_info);
        bytes.push(0); // st_other
        bytes.extend_from_slice(&SHN_UNDEF.to_le_bytes()); // st_shndx

        let mut reader = VecReader::new(bytes);
        ElfSymbol::parse(&mut reader, 1, &MockElfHeader).expect("symbol entry parses")
    }

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            self.0
                .get(start..start + length)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            unimplemented!()
        }
    }

    /// Smallest little-endian [`BinaryReader`] over a byte vector; the crate has no concrete
    /// reader yet.
    struct VecReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        current_index: u64,
    }

    impl VecReader {
        fn new(data: Vec<u8>) -> Self {
            VecReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                current_index: 0,
            }
        }
    }

    impl BinaryReader for VecReader {
        fn length(&self) -> std::io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            std::mem::replace(&mut self.current_index, index)
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(VecReader {
                provider: Rc::clone(&self.provider),
                current_index: new_index,
            })
        }
    }

    fn context_with(
        handler: Option<Arc<dyn ElfRelocationHandler>>,
        load_helper: Arc<MockLoadHelper>,
        symbol_map: HashMap<ElfSymbol, Address>,
    ) -> ElfRelocationContextBase {
        ElfRelocationContextBase::new(handler, load_helper, Arc::new(symbol_map))
    }

    // ---------------------------------------------------------------- tests

    #[test]
    fn missing_handler_is_logged_at_construction() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(None, helper.clone(), HashMap::new());

        assert!(!context.has_relocation_handler());
        assert_eq!(
            helper.helper_log.lock().unwrap().as_slice(),
            [NO_HANDLER_MESSAGE.to_string()]
        );
    }

    #[test]
    fn handler_present_logs_nothing() {
        let helper = Arc::new(MockLoadHelper::new());
        let handler: Arc<dyn ElfRelocationHandler> = Arc::new(MockHandler::new());
        let context = context_with(Some(handler), helper.clone(), HashMap::new());

        assert!(context.has_relocation_handler());
        assert!(helper.helper_log.lock().unwrap().is_empty());
    }

    #[test]
    fn without_symbol_table_only_index_zero_resolves_to_the_null_symbol() {
        let helper = Arc::new(MockLoadHelper::new());
        let mut context = context_with(None, helper, HashMap::new());

        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: false,
            symbol_table: None,
        }));

        // Java installs `new ElfSymbol()` -- the special null symbol -- for index 0 only.
        let null_symbol = context.get_symbol(0).expect("index 0 yields the null symbol");
        assert_eq!(null_symbol, ElfSymbol::new());
        assert!(context.get_symbol(1).is_none());
        assert!(context.get_symbol_name(0).is_none());
    }

    #[test]
    fn with_symbol_table_lookups_are_delegated_to_it() {
        let helper = Arc::new(MockLoadHelper::new());
        let mut context = context_with(None, helper, HashMap::new());

        let symbols = vec![ElfSymbol::new(), symbol(STB_GLOBAL, STT_FUNC)];
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: true,
            symbol_table: Some(Arc::new(MockSymbolTable { symbols })),
        }));

        assert_eq!(context.get_symbol(1).map(|s| s.get_type()), Some(STT_FUNC));
        // Out of range, and -- unlike the no-symbol-table case -- index 0 comes from the table.
        assert!(context.get_symbol(7).is_none());
        assert!(context.get_symbol(0).is_some());
    }

    #[test]
    fn extract_addend_is_the_negation_of_has_addend_relocations() {
        let helper = Arc::new(MockLoadHelper::new());
        let mut context = context_with(None, helper, HashMap::new());

        // No table in hand yet: nothing supplies an addend.
        assert!(context.extract_addend());

        // A RELA table carries its addend, so none has to be extracted.
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: true,
            symbol_table: None,
        }));
        assert!(!context.extract_addend());

        // A REL table does not, so it must be read back from the relocation target.
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: false,
            symbol_table: None,
        }));
        assert!(context.extract_addend());
    }

    #[test]
    fn end_relocation_table_processing_clears_the_table_only() {
        let helper = Arc::new(MockLoadHelper::new());
        let mut context = context_with(None, helper, HashMap::new());

        let symbols = vec![ElfSymbol::new()];
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: true,
            symbol_table: Some(Arc::new(MockSymbolTable { symbols })),
        }));
        context.end_relocation_table_processing();

        assert!(context.relocation_table().is_none());
        // Java's endRelocationTableProcessing leaves symbolTable alone.
        assert!(context.symbol_table().is_some());
    }

    #[test]
    fn process_relocation_without_handler_fails() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(None, helper, HashMap::new());

        let result = context.process_relocation(
            &MockRelocation { symbol_index: 0, type_id: 3 },
            &address(0x2000),
        );

        assert_eq!(result, RelocationResult::FAILURE);
    }

    #[test]
    fn process_relocation_with_unresolvable_symbol_is_an_error() {
        let helper = Arc::new(MockLoadHelper::new());
        let handler = Arc::new(MockHandler::new());
        let mut context =
            context_with(Some(handler.clone()), helper, HashMap::new());

        // No symbol table, so any index but 0 is out of range.
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: false,
            symbol_table: None,
        }));

        let result = context.process_relocation(
            &MockRelocation { symbol_index: 5, type_id: 3 },
            &address(0x2000),
        );

        assert_eq!(result, RelocationResult::FAILURE);
        assert_eq!(
            handler.calls.lock().unwrap().as_slice(),
            [HandlerCall::Error {
                type_id: 3,
                symbol_name: None,
                symbol_index: -1,
                msg: "Invalid symbol index (5)".to_string(),
            }]
        );
    }

    #[test]
    fn process_relocation_for_tls_symbol_is_unsupported() {
        let helper = Arc::new(MockLoadHelper::new());
        let handler = Arc::new(MockHandler::new());
        let mut context = context_with(Some(handler.clone()), helper, HashMap::new());

        let symbols = vec![ElfSymbol::new(), symbol(STB_GLOBAL, STT_TLS)];
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: true,
            symbol_table: Some(Arc::new(MockSymbolTable { symbols })),
        }));

        let result = context.process_relocation(
            &MockRelocation { symbol_index: 1, type_id: 7 },
            &address(0x2000),
        );

        assert_eq!(result, RelocationResult::UNSUPPORTED);
        assert_eq!(
            handler.calls.lock().unwrap().as_slice(),
            [HandlerCall::Warning {
                type_id: 7,
                symbol_name: None,
                symbol_index: 1,
                msg: "Relocation for TLS Symbol not supported".to_string(),
            }]
        );
    }

    #[test]
    fn process_relocation_defers_to_the_handler_for_an_ordinary_symbol() {
        let helper = Arc::new(MockLoadHelper::new());
        let handler = Arc::new(MockHandler::new());
        let mut context = context_with(Some(handler.clone()), helper, HashMap::new());

        let symbols = vec![ElfSymbol::new(), symbol(STB_GLOBAL, STT_FUNC)];
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: true,
            symbol_table: Some(Arc::new(MockSymbolTable { symbols })),
        }));

        let result = context.process_relocation(
            &MockRelocation { symbol_index: 1, type_id: 2 },
            &address(0x2000),
        );

        assert_eq!(result, RelocationResult::new(RelocationStatus::Applied, 4));
        assert_eq!(
            handler.calls.lock().unwrap().as_slice(),
            [HandlerCall::Relocate { symbol_index: 1, type_id: 2 }]
        );
    }

    #[test]
    fn handler_failure_is_logged_and_reported_as_an_error() {
        let helper = Arc::new(MockLoadHelper::new());
        let handler = Arc::new(MockHandler {
            relocate_result: None,
            ..MockHandler::new()
        });
        let mut context = context_with(Some(handler.clone()), helper.clone(), HashMap::new());

        let symbols = vec![ElfSymbol::new(), symbol(STB_GLOBAL, STT_FUNC)];
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: true,
            symbol_table: Some(Arc::new(MockSymbolTable { symbols })),
        }));

        let result = context.process_relocation(
            &MockRelocation { symbol_index: 1, type_id: 2 },
            &address(0x2000),
        );

        assert_eq!(result, RelocationResult::FAILURE);
        assert_eq!(
            helper.helper_log.lock().unwrap().as_slice(),
            ["no memory at address".to_string()]
        );
        let calls = handler.calls.lock().unwrap();
        assert_eq!(
            calls[1],
            HandlerCall::Error {
                type_id: 2,
                symbol_name: None,
                symbol_index: 1,
                msg: "Processing Failure - no memory at address".to_string(),
            }
        );
    }

    #[test]
    fn mark_relocation_error_discards_the_symbol_index_when_a_handler_exists() {
        let helper = Arc::new(MockLoadHelper::new());
        let handler = Arc::new(MockHandler::new());
        let context = context_with(Some(handler.clone()), helper, HashMap::new());

        context.mark_relocation_error(&address(0x2000), 9, 4, Some("memcpy"), "bad offset");

        // Java's markRelocationError passes -1 rather than the caller's symbolIndex here.
        assert_eq!(
            handler.calls.lock().unwrap().as_slice(),
            [HandlerCall::Error {
                type_id: 9,
                symbol_name: Some("memcpy".to_string()),
                symbol_index: -1,
                msg: "bad offset".to_string(),
            }]
        );
    }

    #[test]
    fn mark_relocation_error_without_handler_uses_the_static_markup() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(None, helper.clone(), HashMap::new());

        context.mark_relocation_error(&address(0x2000), 9, 4, Some("memcpy"), "bad offset");

        let messages = helper.log.messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("bad offset"), "got {:?}", messages[0]);
        assert!(messages[0].contains("memcpy"), "got {:?}", messages[0]);
    }

    #[test]
    fn relr_relocation_type_is_zero_without_a_handler() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(None, helper, HashMap::new());
        assert_eq!(context.get_relr_relocation_type(), 0);

        let helper = Arc::new(MockLoadHelper::new());
        let handler = Arc::new(MockHandler { relr_type: 8, ..MockHandler::new() });
        let context = context_with(Some(handler), helper, HashMap::new());
        assert_eq!(context.get_relr_relocation_type(), 8);
    }

    #[test]
    fn symbol_value_is_the_addressable_word_offset_of_the_placement() {
        let sym = symbol(STB_GLOBAL, STT_FUNC);
        let unplaced = symbol(STB_GLOBAL, STT_TLS);

        let mut symbol_map = HashMap::new();
        symbol_map.insert(sym.clone(), address(0x1234));

        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(None, helper, symbol_map);

        assert_eq!(context.get_symbol_address(&sym), Some(address(0x1234)));
        assert_eq!(context.get_symbol_value(&sym), 0x1234);

        // Java's getSymbolValue answers 0 -- not null -- when the symbol has no placement.
        assert_eq!(context.get_symbol_address(&unplaced), None);
        assert_eq!(context.get_symbol_value(&unplaced), 0);
    }

    #[test]
    fn got_value_is_an_error_when_the_load_helper_has_none() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(None, helper, HashMap::new());

        let err = context.get_got_value().expect_err("no GOT was identified");
        assert_eq!(err.0, "Failed to identify _GLOBAL_OFFSET_TABLE_");

        let helper = Arc::new(MockLoadHelper { got_value: Some(0x40_0000), ..MockLoadHelper::new() });
        let context = context_with(None, helper, HashMap::new());
        assert_eq!(context.get_got_value().unwrap(), 0x40_0000);
    }

    #[test]
    fn relocation_address_wraps_within_the_address_space() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(None, helper, HashMap::new());

        assert_eq!(
            context.get_relocation_address(&address(0x1000), 0x24),
            address(0x1024)
        );
    }

    #[test]
    fn image_base_word_adjustment_comes_from_the_load_helper() {
        let helper =
            Arc::new(MockLoadHelper { image_base_word_adjustment: -0x1000, ..MockLoadHelper::new() });
        let context = context_with(None, helper, HashMap::new());

        assert_eq!(context.get_image_base_word_adjustment_offset(), -0x1000);
    }

    #[test]
    fn generic_context_is_used_when_the_handler_defines_none() {
        let helper: Arc<dyn ElfLoadHelper> = Arc::new(MockLoadHelper::new());
        let handler: Arc<dyn ElfRelocationHandler> = Arc::new(MockHandler::new());

        let context = ElfRelocationContextBase::get_relocation_context(
            helper,
            Arc::new(HashMap::new()),
            Some(handler),
        );

        assert!(context.base().has_relocation_handler());
        assert_eq!(context.get_relr_relocation_type(), 0);
    }
}
