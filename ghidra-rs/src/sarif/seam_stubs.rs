//! Minimal placeholder types for core types that `sarif` code references before the real Rust
//! port of that type exists yet. Each stub exposes only the members needed by the type(s) that
//! currently reference it, and is expected to be replaced (or grown into a full port) once that
//! Java class is ported. See `STUBS.tsv` for provenance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::docking::settings::settings::Settings;
use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::address::{Address, AddressFactory, AddressRange, AddressSet, AddressSetView};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::{Bookmark, CodeUnit, GhidraClass, Instruction, Program, ProgramModule};
use crate::program::model::mem::MemoryBlock;
use crate::program::model::reloc::Relocation;
use crate::program::model::symbol::source_type::SourceType;
use crate::program::model::symbol::{Namespace, Symbol};
use crate::program::seam_stubs::FlowOverride;
use crate::util::exception::DuplicateNameException;
use crate::util::task::TaskMonitor;

/// Placeholder for the abstract Java base class `sarif.managers.SarifMgr`, which every
/// `*SarifMgr` (including [`BookmarksSarifMgr`](crate::sarif::managers::BookmarksSarifMgr))
/// extends. Java's version is an abstract class, not an interface, so this is a plain struct
/// composed into the leaf manager rather than a `dyn`-dispatched trait or an inheritance
/// relationship (Rust has neither).
///
/// Only the members `BookmarksSarifMgr` uses are modeled: the `key` field and the `getLocation`
/// helper. `getLocation` defers to `sarif.SarifUtils.getLocations`
/// (`Ghidra/Features/Sarif/src/main/java/sarif/SarifUtils.java`), which is not ported yet, so it
/// always reports "no location found" -- the same thing an empty `AddressSet.getMinAddress()`
/// returns in Java.
pub struct SarifMgr {
    key: String,
}

impl SarifMgr {
    /// `new SarifMgr(String key, Program program, MessageLog log)`, minus the `program`/`log`
    /// fields the base class also stores: `BookmarksSarifMgr` keeps its own `log` and derives
    /// what it needs from `program` directly instead of caching them a second time here.
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// `SarifMgr.getKey()`.
    pub fn get_key(&self) -> &str {
        &self.key
    }

    /// `SarifMgr.getLocation(Map<String, Object>)`. Placeholder pending the `SarifUtils` port.
    pub fn get_location(
        &self,
        _result: &HashMap<String, serde_json::Value>,
    ) -> Result<Option<Address>, AddressOverflowException> {
        Ok(None)
    }

    /// `SarifMgr.getLocations(Map<String, Object>, AddressSet)`. Placeholder pending the
    /// `SarifUtils` port: never adds any addresses to `set`, matching
    /// [`get_location`](Self::get_location)'s always-empty result.
    pub fn get_locations(
        &self,
        _result: &HashMap<String, serde_json::Value>,
        set: &mut AddressSet,
    ) -> Result<(), AddressOverflowException> {
        let _ = set;
        Ok(())
    }

    /// `SarifMgr.getSourceType(String)`. Takes the caller's log explicitly, since this field-less
    /// stub does not hold the base class's `log`.
    pub fn get_source_type(log: &MessageLog, signature_source: Option<&str>) -> SourceType {
        let Some(signature_source) = signature_source else {
            return SourceType::Imported;
        };
        match signature_source {
            "DEFAULT" => SourceType::Default,
            "ANALYSIS" => SourceType::Analysis,
            "AI" => SourceType::AI,
            "IMPORTED" => SourceType::Imported,
            "USER_DEFINED" => SourceType::UserDefined,
            _ => {
                log.append_msg(format!("Unknown SourceType: {signature_source}"));
                SourceType::Imported
            }
        }
    }

    /// `SarifMgr.walkNamespace(Namespace, String, Address, SourceType, Boolean)`. Takes the
    /// caller's `Program` handle explicitly, since this field-less stub does not hold the base
    /// class's `program`.
    ///
    /// Java distinguishes a plain namespace lookup (`SymbolTable.getNamespace`) that falls back to
    /// either `SymbolTable.createClass` or `NamespaceUtils.createNamespaceHierarchy` depending on
    /// `is_class`; the ported [`SymbolTable`](crate::program::model::symbol::SymbolTable) trait has
    /// neither a class-typed constructor nor a namespace-only (non-creating) lookup yet, so both
    /// cases collapse onto its combined
    /// [`get_or_create_name_space`](crate::program::model::symbol::SymbolTable::get_or_create_name_space),
    /// which loses the `is_class` distinction until `SymbolTable` grows a `create_class`
    /// equivalent. `Ok(None)` is Java's `null` return: a `FUN_`-prefixed namespace deferred until
    /// the function it names exists.
    pub fn walk_namespace(
        program: &mut Arc<dyn Program>,
        parent: Arc<dyn Namespace>,
        namespace: &str,
        addr: Option<&Address>,
        source_type: SourceType,
        is_class: bool,
    ) -> Result<Option<Arc<dyn Namespace>>, String> {
        let Some(sep) = namespace.find("::").filter(|&sep| sep > 0) else {
            return Ok(Some(parent));
        };
        let tag = &namespace[..sep];
        let rest = namespace[sep + 2..].to_string();

        if let Some(addr) = addr {
            let func = Arc::get_mut(program)
                .and_then(|p| p.get_function_manager())
                .and_then(|fm| fm.get_function_containing(addr));
            match func {
                Some(func) => {
                    if func.get_name_with_path(true) == tag {
                        if let Some(func_ns) = func.get_symbol().as_namespace() {
                            return Self::walk_namespace(program, func_ns, &rest, Some(addr), source_type, is_class);
                        }
                    }
                }
                None => {
                    if tag.starts_with("FUN_") {
                        return Ok(None); // Defer this until later
                    }
                }
            }
        }

        let child = match Arc::get_mut(program).and_then(|p| p.get_symbol_table()) {
            Some(symbol_table) => symbol_table
                .get_or_create_name_space(parent.clone(), tag, source_type)
                .map_err(|_| format!("Error creating namespace for {tag}"))?,
            None => parent.clone(),
        };

        Self::walk_namespace(program, child, &rest, addr, source_type, is_class)
    }

    /// `SarifMgr.parseAddress(AddressFactory, String)`, referenced by
    /// [`ProgramTreeSarifMgr`](crate::sarif::managers::ProgramTreeSarifMgr). Java returns `null`
    /// for a `null` input and otherwise throws an (unchecked) `RuntimeException` when the factory
    /// fails to resolve the string; the latter is modeled as `Err` here since none of this crate's
    /// error types are unchecked.
    pub fn parse_address(
        factory: Option<&dyn AddressFactory>,
        addr_string: Option<&str>,
    ) -> Result<Option<Address>, String> {
        let Some(addr_string) = addr_string else {
            return Ok(None);
        };
        factory
            .and_then(|factory| factory.get_address(addr_string))
            .map(Some)
            .ok_or_else(|| format!("Error converting {addr_string} to address"))
    }

    /// `SarifMgr.parseLong(String)`. Mirrors `NumericUtilities.parseLong`/`parseHexLong`: an
    /// optional leading `-`, then an optional `0x` prefix selecting radix 16 over the default 10.
    /// Java's version throws an unchecked `NumberFormatException` on failure; that is modeled here
    /// as `Err` since none of this crate's error types are unchecked.
    pub fn parse_long(long_str: &str) -> Result<i64, String> {
        let (is_negative, rest) = match long_str.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, long_str),
        };
        let (radix, digits) = match rest.strip_prefix("0x") {
            Some(hex) => (16, hex),
            None => (10, rest),
        };
        let val = i64::from_str_radix(digits, radix).map_err(|_| long_str.to_string())?;
        Ok(if is_negative { -val } else { val })
    }
}

/// Placeholder for `sarif.SarifProgramOptions`, referenced by
/// [`BookmarksSarifMgr::read`](crate::sarif::managers::BookmarksSarifMgr::read) and
/// [`MarkupSarifMgr::read`](crate::sarif::managers::MarkupSarifMgr::read). Java's version is a
/// concrete class, not an interface, so this is a plain struct. Only the flags those managers
/// read are modeled; [`Default`] carries the same initial values Java's field initializers do.
#[derive(Debug, Clone, Copy)]
pub struct SarifProgramOptions {
    pub overwrite_bookmark_conflicts: bool,
    pub overwrite_reference_conflicts: bool,
    pub overwrite_symbol_conflicts: bool,
    pub functions: bool,
    pub external_libraries: bool,
}

impl SarifProgramOptions {
    /// `SarifProgramOptions.isOverwriteBookmarkConflicts()`.
    pub fn is_overwrite_bookmark_conflicts(&self) -> bool {
        self.overwrite_bookmark_conflicts
    }

    /// `SarifProgramOptions.isOverwriteReferenceConflicts()`.
    pub fn is_overwrite_reference_conflicts(&self) -> bool {
        self.overwrite_reference_conflicts
    }

    /// `SarifProgramOptions.isOverwriteSymbolConflicts()`, referenced by
    /// [`SymbolTableSarifMgr::read`](crate::sarif::managers::SymbolTableSarifMgr::read).
    pub fn is_overwrite_symbol_conflicts(&self) -> bool {
        self.overwrite_symbol_conflicts
    }

    /// `SarifProgramOptions.isFunctions()`.
    pub fn is_functions(&self) -> bool {
        self.functions
    }

    /// `SarifProgramOptions.isExternalLibraries()`.
    pub fn is_external_libraries(&self) -> bool {
        self.external_libraries
    }
}

impl Default for SarifProgramOptions {
    /// The values `new SarifProgramOptions()` starts out with: every flag modeled here is `true`.
    fn default() -> Self {
        Self {
            overwrite_bookmark_conflicts: true,
            overwrite_reference_conflicts: true,
            overwrite_symbol_conflicts: true,
            functions: true,
            external_libraries: true,
        }
    }
}

/// Placeholder for `ghidra.app.util.importer.MessageLog`, referenced by `sarif` managers.
/// Concrete stub, since there is nothing to dispatch over (Java's version is a concrete class):
/// a real, if minimal, in-memory log rather than an `unimplemented!()` placeholder. Only the two
/// methods `BookmarksSarifMgr` calls (`appendMsg`, `appendException`) are modeled.
#[derive(Debug, Default)]
pub struct MessageLog {
    messages: Mutex<Vec<String>>,
}

impl MessageLog {
    /// `new MessageLog()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// `MessageLog.appendMsg(String)`.
    pub fn append_msg(&self, message: impl Into<String>) {
        self.messages.lock().unwrap().push(message.into());
    }

    /// `MessageLog.appendException(Throwable)`.
    pub fn append_exception(&self, err: &dyn std::error::Error) {
        self.messages.lock().unwrap().push(err.to_string());
    }

    /// The messages recorded so far, in append order.
    pub fn messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }
}

/// Placeholder for `sarif.export.relocs.SarifRelocationWriter`, referenced by
/// [`RelocationTableSarifMgr::write_as_sarif`](crate::sarif::managers::RelocationTableSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled; the `genRoot`/`AbstractExtWriter` machinery that turns the relocations
/// into SARIF JSON is pending that class's own port.
pub struct SarifRelocationWriter {
    pub relocations: Vec<Relocation>,
}

impl SarifRelocationWriter {
    /// `new SarifRelocationWriter(List<Relocation> target, Writer baseWriter)`, minus the (always
    /// `null`, here) base writer.
    pub fn new(relocations: Vec<Relocation>) -> Self {
        Self { relocations }
    }
}

/// Placeholder for `sarif.export.symbols.SarifSymbolWriter`, referenced by
/// [`SymbolTableSarifMgr::write_as_sarif`](crate::sarif::managers::SymbolTableSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled; the `genRoot`/`AbstractExtWriter` machinery that turns the symbols into
/// SARIF JSON is pending that class's own port.
pub struct SarifSymbolWriter {
    pub symbols: Vec<Arc<dyn Symbol>>,
}

impl SarifSymbolWriter {
    /// `new SarifSymbolWriter(List<Symbol> target, Writer baseWriter)`, minus the (always `null`,
    /// here) base writer.
    pub fn new(symbols: Vec<Arc<dyn Symbol>>) -> Self {
        Self { symbols }
    }
}

/// Placeholder for `sarif.export.bkmk.SarifBookmarkWriter`, referenced by
/// [`BookmarksSarifMgr::write_as_sarif`](crate::sarif::managers::BookmarksSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled; the `genRoot`/`AbstractExtWriter` machinery that turns the bookmarks
/// into SARIF JSON is pending that class's own port.
pub struct SarifBookmarkWriter {
    pub bookmarks: Vec<Arc<dyn Bookmark>>,
}

impl SarifBookmarkWriter {
    /// `new SarifBookmarkWriter(List<Bookmark> target, Writer baseWriter)`, minus the (always
    /// `null`, here) base writer.
    pub fn new(bookmarks: Vec<Arc<dyn Bookmark>>) -> Self {
        Self { bookmarks }
    }
}

/// Placeholder for `sarif.export.SarifWriterTask`, referenced by
/// [`BookmarksSarifMgr::write_as_sarif`](crate::sarif::managers::BookmarksSarifMgr::write_as_sarif)
/// and [`CodeSarifMgr::write_as_sarif`](crate::sarif::managers::CodeSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct; it is generic
/// over the writer type (Java's `AbstractIsfWriter`) since more than one `*SarifMgr` now
/// constructs one with its own writer. Only the constructor and `run` are modeled; `run`'s real
/// behavior (flushing the writer's results into the shared `JsonArray`) is pending each writer's
/// own port, so this is a no-op for now.
pub struct SarifWriterTask<W> {
    pub tag: String,
    pub writer: W,
}

impl<W> SarifWriterTask<W> {
    /// `new SarifWriterTask(String tag, AbstractIsfWriter writer, JsonArray results)`, minus the
    /// `results` array (passed to [`run`](Self::run) instead, matching `Task.run(TaskMonitor)`'s
    /// signature).
    pub fn new(tag: impl Into<String>, writer: W) -> Self {
        Self { tag: tag.into(), writer }
    }

    /// `SarifWriterTask.run(TaskMonitor)`.
    pub fn run(&self, _monitor: &dyn TaskMonitor, _results: &mut Vec<serde_json::Value>) {}
}

/// Placeholder for `ghidra.util.task.TaskLauncher`, referenced by
/// [`BookmarksSarifMgr::write_as_sarif`](crate::sarif::managers::BookmarksSarifMgr::write_as_sarif)
/// and [`CodeSarifMgr::write_as_sarif`](crate::sarif::managers::CodeSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// modal two-argument constructor `writeAsSARIF` uses (`new TaskLauncher(task, null)`) is
/// modeled, and since there is no GUI here it just runs the task synchronously.
pub struct TaskLauncher;

impl TaskLauncher {
    /// `new TaskLauncher(Task task, Component parent)`, minus the (always `null`, here) parent
    /// component.
    pub fn launch<W>(task: &SarifWriterTask<W>, monitor: &dyn TaskMonitor, results: &mut Vec<serde_json::Value>) {
        task.run(monitor, results);
    }
}

/// Placeholder for `sarif.export.trees.SarifTreeWriter`, referenced by
/// [`ProgramTreeSarifMgr::write_as_sarif`](crate::sarif::managers::ProgramTreeSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled; the `genRoot`/`AbstractExtWriter` machinery that turns the tree
/// hierarchy into SARIF JSON is pending that class's own port.
pub struct SarifTreeWriter {
    /// `List<Pair<String, ProgramModule>> request`, one `(treeName, rootModule)` pair per tree.
    pub request: Vec<(String, Arc<dyn ProgramModule>)>,
}

impl SarifTreeWriter {
    /// `new SarifTreeWriter(List<Pair<String, ProgramModule>> req, Writer baseWriter)`, minus the
    /// (always `null`, here) base writer.
    pub fn new(request: Vec<(String, Arc<dyn ProgramModule>)>) -> Self {
        Self { request }
    }
}

/// Placeholder for `sarif.export.comments.SarifCommentWriter`, referenced by
/// [`CommentsSarifMgr::write_as_sarif0`](crate::sarif::managers::CommentsSarifMgr::write_as_sarif0)
/// and
/// [`CommentsSarifMgr::write_as_sarif1`](crate::sarif::managers::CommentsSarifMgr::write_as_sarif1).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled, mirroring `new SarifCommentWriter(List<Pair<CodeUnit, Pair<String,
/// String>>> target0, List<Pair<Address, Pair<String, String>>> target1)`; the `genRoot`/
/// `AbstractExtWriter` machinery that turns the comments into SARIF JSON is pending that class's
/// own port. `Pair<String, String>` (the SARIF tag and comment text) is modeled as a plain tuple
/// rather than a generic `Pair` stub, since that is all a two-element pair is; likewise the outer
/// `Pair<CodeUnit, _>`/`Pair<Address, _>` are flattened into a tuple's first element.
pub struct SarifCommentWriter {
    pub code_unit_comments: Vec<(Arc<dyn CodeUnit>, (String, String))>,
    pub address_comments: Vec<(Address, (String, String))>,
}

impl SarifCommentWriter {
    /// `new SarifCommentWriter(List<Pair<CodeUnit, Pair<String, String>>> target0,
    /// List<Pair<Address, Pair<String, String>>> target1)`, minus the (always `null`, here) base
    /// writer.
    pub fn new(
        code_unit_comments: Vec<(Arc<dyn CodeUnit>, (String, String))>,
        address_comments: Vec<(Address, (String, String))>,
    ) -> Self {
        Self {
            code_unit_comments,
            address_comments,
        }
    }
}

/// Placeholder for `sarif.export.equates.SarifEquateWriter`, referenced by
/// [`EquatesSarifMgr::write_as_sarif`](crate::sarif::managers::EquatesSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled, mirroring `new SarifEquateWriter(List<Equate> target, Writer
/// baseWriter)`; the `genRoot`/`AbstractExtWriter` machinery that turns the equates into SARIF
/// JSON is pending that class's own port.
pub struct SarifEquateWriter {
    pub equates: Vec<crate::program::model::symbol::SimpleEquate>,
}

impl SarifEquateWriter {
    /// `new SarifEquateWriter(List<Equate> target, Writer baseWriter)`, minus the (always `null`,
    /// here) base writer.
    pub fn new(equates: Vec<crate::program::model::symbol::SimpleEquate>) -> Self {
        Self { equates }
    }
}

/// Placeholder for `sarif.export.ep.SarifEntryPointWriter`, referenced by
/// [`ExtEntryPointSarifMgr::write_as_sarif`](crate::sarif::managers::ExtEntryPointSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled, mirroring `new SarifEntryPointWriter(List<Address> target, Writer
/// baseWriter)`; the `genRoot`/`AbstractExtWriter` machinery that turns the entry points into
/// SARIF JSON is pending that class's own port.
pub struct SarifEntryPointWriter {
    pub addresses: Vec<Address>,
}

impl SarifEntryPointWriter {
    /// `new SarifEntryPointWriter(List<Address> target, Writer baseWriter)`, minus the (always
    /// `null`, here) base writer.
    pub fn new(addresses: Vec<Address>) -> Self {
        Self { addresses }
    }
}

/// Placeholder for `sarif.export.code.SarifCodeWriter`, referenced by
/// [`CodeSarifMgr::write_as_sarif`](crate::sarif::managers::CodeSarifMgr::write_as_sarif). Java's
/// version is a concrete class, not an interface, so this is a plain struct. Only the constructor
/// is modeled; the `genRoot`/`AbstractExtWriter` machinery that turns the code ranges and flow
/// overrides into SARIF JSON is pending that class's own port.
pub struct SarifCodeWriter {
    pub blocks: Vec<AddressRange>,
    pub overrides: Vec<(Arc<dyn Instruction>, FlowOverride)>,
}

impl SarifCodeWriter {
    /// `new SarifCodeWriter(List<AddressRange> target0, List<Pair<Instruction, FlowOverride>>
    /// target1, Writer baseWriter)`, minus the (always `null`, here) base writer. `Pair<Instruction,
    /// FlowOverride>` is modeled as a plain tuple rather than a generic `Pair` stub, since that is
    /// all a two-element pair is.
    pub fn new(blocks: Vec<AddressRange>, overrides: Vec<(Arc<dyn Instruction>, FlowOverride)>) -> Self {
        Self { blocks, overrides }
    }
}

/// Placeholder for `sarif.export.extlib.SarifExternalLibraryWriter`, referenced by
/// [`ExternalLibSarifMgr::write_ext_as_sarif`](crate::sarif::managers::ExternalLibSarifMgr::write_ext_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor's library-name list is modeled; the `ExternalManager` collaborator (needed to look
/// up each library's path and locations) and the `genRoot`/`AbstractExtWriter` machinery that
/// turns them into SARIF JSON are pending that class's own port.
pub struct SarifExternalLibraryWriter {
    pub library_names: Vec<String>,
}

impl SarifExternalLibraryWriter {
    /// `new SarifExternalLibraryWriter(ExternalManager externalManager, List<String> request,
    /// Writer baseWriter)`, minus the manager (pending its own port) and the (always `null`, here)
    /// base writer.
    pub fn new(library_names: Vec<String>) -> Self {
        Self { library_names }
    }
}

/// Placeholder for `sarif.export.extlib.SarifClassesNamespaceWriter`, referenced by
/// [`ExternalLibSarifMgr::write_namespace_as_sarif`](crate::sarif::managers::ExternalLibSarifMgr::write_namespace_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor's class list is modeled; the `ExternalManager`/`SymbolTable` collaborators (needed
/// to walk each class's external symbols) and the `genRoot`/`AbstractExtWriter` machinery that
/// turns them into SARIF JSON are pending that class's own port.
pub struct SarifClassesNamespaceWriter {
    pub classes: Vec<Arc<dyn GhidraClass>>,
}

impl SarifClassesNamespaceWriter {
    /// `new SarifClassesNamespaceWriter(ExternalManager externalManager, SymbolTable symbolTable,
    /// List<GhidraClass> request, Writer baseWriter)`, minus the manager/table (pending their own
    /// ports) and the (always `null`, here) base writer.
    pub fn new(classes: Vec<Arc<dyn GhidraClass>>) -> Self {
        Self { classes }
    }
}

/// Placeholder for `sarif.export.ref.SarifReferenceWriter`, referenced by
/// [`MarkupSarifMgr::write_refs_as_sarif`](crate::sarif::managers::MarkupSarifMgr::write_refs_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor's address list is modeled; the `ReferenceManager` collaborator (needed to look up
/// the references leaving each address) and the `genRoot`/`AbstractExtWriter` machinery that turns
/// them into SARIF JSON are pending that class's own port.
pub struct SarifReferenceWriter {
    pub references: Vec<Address>,
}

impl SarifReferenceWriter {
    /// `new SarifReferenceWriter(ReferenceManager referenceManager, List<Address> request, Writer
    /// baseWriter)`, minus the manager (pending its own port) and the (always `null`, here) base
    /// writer.
    pub fn new(references: Vec<Address>) -> Self {
        Self { references }
    }
}

/// Placeholder for `sarif.export.ref.SarifEquateRefWriter`, referenced by
/// [`MarkupSarifMgr::write_equate_refs_as_sarif`](crate::sarif::managers::MarkupSarifMgr::write_equate_refs_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor's address set is modeled -- as an owned [`AddressSet`] snapshot, since the writer
/// outlives the borrowed view it is built from; the `EquateTable` collaborator and the
/// `genRoot`/`AbstractExtWriter` machinery are pending that class's own port.
pub struct SarifEquateRefWriter {
    pub set: AddressSet,
}

impl SarifEquateRefWriter {
    /// `new SarifEquateRefWriter(EquateTable equateTable, AddressSetView set, Writer baseWriter)`,
    /// minus the table (pending its own port) and the (always `null`, here) base writer.
    pub fn new(set: AddressSet) -> Self {
        Self { set }
    }
}

/// Placeholder for `ghidra.program.disassemble.Disassembler`, referenced by
/// [`CodeSarifMgr::disassemble`](crate::sarif::managers::CodeSarifMgr::disassemble). Java's
/// version is a concrete class, not an interface, so this is a plain struct. Only the two methods
/// `CodeSarifMgr` calls (`getDisassembler`, `disassemble`) are modeled; both are no-ops (disassembles
/// nothing) pending the real disassembler port, which matches a disassembler that finds no valid
/// instructions at any candidate address.
pub struct Disassembler;

impl Disassembler {
    /// `Disassembler.getDisassembler(Program, TaskMonitor, DisassemblerMessageListener)`.
    pub fn get_disassembler(
        _program: &dyn Program,
        _monitor: &dyn TaskMonitor,
        _listener: &dyn crate::program::disassemble::DisassemblerMessageListener,
    ) -> Self {
        Disassembler
    }

    /// `Disassembler.disassemble(Address, AddressSetView)`.
    pub fn disassemble(&self, _start_addr: &Address, _restricted_set: &dyn AddressSetView) -> AddressSet {
        AddressSet::new()
    }
}

// ---------------------------------------------------------------------------
// Placeholders for the concrete `*DataType` classes `DataTypesSarifMgr` builds
// ---------------------------------------------------------------------------
//
// `ghidra.program.model.data`'s *interfaces* (`DataType`, `Structure`, `Union`, `Enum`,
// `TypeDef`, ...) are all ported already, and this module reuses them. What is missing is the
// concrete classes that can actually be *constructed* -- `StructureDataType`, `UnionDataType`,
// `EnumDataType`, `TypedefDataType`, `PointerDataType`, `ArrayDataType` and
// `FunctionDefinitionDataType` -- each of which exists in the crate only as a (constructor-less)
// trait. `DataTypesSarifMgr` is nothing but a factory for those classes, so the placeholders
// below stand in for their constructors. Each records the state `DataTypesSarifMgr` gives it and
// implements just enough of [`DataType`] (name, length, category path, description) for the
// manager's own path/lookup logic to behave the way the Java code does; the real layout,
// alignment and resolution machinery arrives with each class's own port.

/// One value stored in a [`SharedSettings`] map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingValue {
    /// Written by `Settings.setLong`.
    Long(i64),
    /// Written by `Settings.setString`.
    String(String),
}

/// A minimal [`Settings`] implementation that is shared by handle rather than by value.
///
/// Not a port of a specific Java class: it exists because `DataType.getDefaultSettings()` returns
/// an owned `Box<dyn Settings>` in Rust where Java returns a live reference into the data type.
/// Cloning a `SharedSettings` clones the handle, so
/// [`DataTypesSarifMgr::process_settings`](crate::sarif::managers::DataTypesSarifMgr) writing
/// through a boxed clone is visible on the data type it came from, exactly as in Java.
#[derive(Debug, Clone, Default)]
pub struct SharedSettings(Arc<Mutex<HashMap<String, SettingValue>>>);

impl SharedSettings {
    /// A fresh, empty settings map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every name/value pair written so far.
    pub fn entries(&self) -> HashMap<String, SettingValue> {
        self.0.lock().unwrap().clone()
    }
}

impl Settings for SharedSettings {
    fn get_long(&self, name: &str) -> Option<i64> {
        match self.0.lock().unwrap().get(name) {
            Some(SettingValue::Long(value)) => Some(*value),
            _ => None,
        }
    }

    fn get_string(&self, name: &str) -> Option<String> {
        match self.0.lock().unwrap().get(name) {
            Some(SettingValue::String(value)) => Some(value.clone()),
            _ => None,
        }
    }

    fn set_long(&mut self, name: &str, value: i64) {
        self.0.lock().unwrap().insert(name.to_string(), SettingValue::Long(value));
    }

    fn set_string(&mut self, name: &str, value: &str) {
        self.0
            .lock()
            .unwrap()
            .insert(name.to_string(), SettingValue::String(value.to_string()));
    }

    fn clear_setting(&mut self, name: &str) {
        self.0.lock().unwrap().remove(name);
    }

    fn clear_all_settings(&mut self) {
        self.0.lock().unwrap().clear();
    }

    fn get_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.0.lock().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_empty()
    }
}

/// Models the `(Composite) dt` cast `DataTypesSarifMgr.addDataType` performs before applying the
/// packing it recorded while reading a struct or union.
///
/// Rust cannot recover a `&mut dyn Composite` from an `Arc<dyn DataType>`, so `addDataType` takes
/// the concrete placeholder by value and applies packing through this trait instead. The
/// no-op default bodies stand in for Java's cast simply not matching a non-composite.
pub trait CompositePacking {
    /// `Composite.setPackingEnabled(boolean)`.
    fn set_packing_enabled(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// `Composite.setExplicitPackingValue(int)`.
    fn set_explicit_packing_value(&mut self, value: i32) {
        let _ = value;
    }
}

/// One component recorded by [`StructureDataType`] or [`UnionDataType`].
///
/// Stands in for the `DataTypeComponent` those classes hand back. Only what `DataTypesSarifMgr`
/// does with the returned component -- read its default settings -- plus the field values it just
/// supplied are modeled, so this is a plain record rather than an implementation of the (ported)
/// `DataTypeComponent` trait.
#[derive(Clone)]
pub struct PlaceholderDataTypeComponent {
    pub ordinal: i32,
    pub offset: i32,
    pub length: i32,
    pub field_name: Option<String>,
    pub comment: Option<String>,
    /// `bitOffset`/`bitSize`, set only for a bit-field component.
    pub bit_field: Option<(i32, i32)>,
    pub data_type: Arc<dyn DataType>,
    settings: SharedSettings,
}

impl PlaceholderDataTypeComponent {
    /// `DataTypeComponent.getDefaultSettings()`.
    pub fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }

    /// The settings written through [`get_default_settings`](Self::get_default_settings).
    pub fn settings(&self) -> &SharedSettings {
        &self.settings
    }
}

/// Placeholder for `ghidra.program.model.data.StructureDataType`'s
/// `StructureDataType(CategoryPath, String, int, DataTypeManager)` constructor. Records the
/// components `DataTypesSarifMgr` adds rather than laying them out.
#[derive(Clone)]
pub struct StructureDataType {
    category_path: CategoryPath,
    name: String,
    length: i32,
    description: String,
    settings: SharedSettings,
    /// Components in the order `DataTypesSarifMgr` supplied them.
    pub components: Vec<PlaceholderDataTypeComponent>,
    pub explicit_minimum_alignment: Option<i32>,
    pub packing_enabled: Option<bool>,
    pub explicit_packing_value: Option<i32>,
}

impl StructureDataType {
    /// `new StructureDataType(CategoryPath path, String name, int length, DataTypeManager dtm)`,
    /// minus the data type manager (this placeholder is never resolved into one).
    pub fn new(category_path: CategoryPath, name: &str, length: i32) -> Self {
        Self {
            category_path,
            name: name.to_string(),
            length,
            description: String::new(),
            settings: SharedSettings::new(),
            components: Vec::new(),
            explicit_minimum_alignment: None,
            packing_enabled: None,
            explicit_packing_value: None,
        }
    }

    /// `Composite.setExplicitMinimumAlignment(int)`.
    pub fn set_explicit_minimum_alignment(&mut self, min_alignment: i32) {
        self.explicit_minimum_alignment = Some(min_alignment);
    }

    /// `Structure.add(DataType, int length, String name, String comment)`: appends at the current
    /// end of the structure and grows it by `length`.
    pub fn add(
        &mut self,
        data_type: Arc<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> PlaceholderDataTypeComponent {
        let offset = self.length.max(0);
        self.length = offset + length.max(0);
        self.push(offset, length, field_name, comment, None, data_type)
    }

    /// `Structure.replaceAtOffset(int offset, DataType, int length, String name, String comment)`.
    pub fn replace_at_offset(
        &mut self,
        offset: i32,
        data_type: Arc<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> PlaceholderDataTypeComponent {
        self.components.retain(|c| c.offset != offset);
        self.length = self.length.max(offset + length.max(0));
        self.push(offset, length, field_name, comment, None, data_type)
    }

    /// `Structure.insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset, DataType,
    /// int bitSize, String name, String comment)`.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_bit_field_at(
        &mut self,
        byte_offset: i32,
        byte_width: i32,
        bit_offset: i32,
        data_type: Arc<dyn DataType>,
        bit_size: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> PlaceholderDataTypeComponent {
        self.length = self.length.max(byte_offset + byte_width.max(0));
        self.push(
            byte_offset,
            byte_width,
            field_name,
            comment,
            Some((bit_offset, bit_size)),
            data_type,
        )
    }

    fn push(
        &mut self,
        offset: i32,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
        bit_field: Option<(i32, i32)>,
        data_type: Arc<dyn DataType>,
    ) -> PlaceholderDataTypeComponent {
        let component = PlaceholderDataTypeComponent {
            ordinal: self.components.len() as i32,
            offset,
            length,
            field_name,
            comment,
            bit_field,
            data_type,
            settings: SharedSettings::new(),
        };
        self.components.push(component.clone());
        component
    }
}

impl CompositePacking for StructureDataType {
    fn set_packing_enabled(&mut self, enabled: bool) {
        self.packing_enabled = Some(enabled);
    }

    fn set_explicit_packing_value(&mut self, value: i32) {
        self.explicit_packing_value = Some(value);
    }
}

impl DataType for StructureDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        self.category_path = path;
        Ok(())
    }

    fn get_description(&self) -> String {
        self.description.clone()
    }

    fn set_description(
        &mut self,
        description: &str,
    ) -> Result<(), crate::program::model::data::data_type::UnsupportedOperationError> {
        self.description = description.to_string();
        Ok(())
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }

    fn is_structure(&self) -> bool {
        true
    }
}

/// Placeholder for `ghidra.program.model.data.UnionDataType`'s
/// `UnionDataType(CategoryPath, String)` constructor. See [`StructureDataType`].
#[derive(Clone)]
pub struct UnionDataType {
    category_path: CategoryPath,
    name: String,
    description: String,
    settings: SharedSettings,
    /// Members in the order `DataTypesSarifMgr` supplied them.
    pub components: Vec<PlaceholderDataTypeComponent>,
    pub explicit_minimum_alignment: Option<i32>,
    pub packing_enabled: Option<bool>,
    pub explicit_packing_value: Option<i32>,
}

impl UnionDataType {
    /// `new UnionDataType(CategoryPath path, String name)`.
    pub fn new(category_path: CategoryPath, name: &str) -> Self {
        Self {
            category_path,
            name: name.to_string(),
            description: String::new(),
            settings: SharedSettings::new(),
            components: Vec::new(),
            explicit_minimum_alignment: None,
            packing_enabled: None,
            explicit_packing_value: None,
        }
    }

    /// `Composite.setExplicitMinimumAlignment(int)`.
    pub fn set_explicit_minimum_alignment(&mut self, min_alignment: i32) {
        self.explicit_minimum_alignment = Some(min_alignment);
    }

    /// `Composite.add(DataType, int length, String name, String comment)`.
    pub fn add(
        &mut self,
        data_type: Arc<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> PlaceholderDataTypeComponent {
        self.push(length, field_name, comment, None, data_type)
    }

    /// `Union.addBitField(DataType, int bitSize, String name, String comment)`.
    pub fn add_bit_field(
        &mut self,
        data_type: Arc<dyn DataType>,
        bit_size: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> PlaceholderDataTypeComponent {
        let length = data_type.get_length();
        self.push(length, field_name, comment, Some((0, bit_size)), data_type)
    }

    fn push(
        &mut self,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
        bit_field: Option<(i32, i32)>,
        data_type: Arc<dyn DataType>,
    ) -> PlaceholderDataTypeComponent {
        let component = PlaceholderDataTypeComponent {
            ordinal: self.components.len() as i32,
            offset: 0,
            length,
            field_name,
            comment,
            bit_field,
            data_type,
            settings: SharedSettings::new(),
        };
        self.components.push(component.clone());
        component
    }
}

impl CompositePacking for UnionDataType {
    fn set_packing_enabled(&mut self, enabled: bool) {
        self.packing_enabled = Some(enabled);
    }

    fn set_explicit_packing_value(&mut self, value: i32) {
        self.explicit_packing_value = Some(value);
    }
}

impl DataType for UnionDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    /// A union is as long as its longest member.
    fn get_length(&self) -> i32 {
        self.components.iter().map(|c| c.length).max().unwrap_or(0)
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        self.category_path = path;
        Ok(())
    }

    fn get_description(&self) -> String {
        self.description.clone()
    }

    fn set_description(
        &mut self,
        description: &str,
    ) -> Result<(), crate::program::model::data::data_type::UnsupportedOperationError> {
        self.description = description.to_string();
        Ok(())
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }

    fn is_union(&self) -> bool {
        true
    }
}

/// Placeholder for `ghidra.program.model.data.EnumDataType`'s
/// `EnumDataType(CategoryPath, String, int, DataTypeManager)` constructor. See
/// [`StructureDataType`].
#[derive(Clone)]
pub struct EnumDataType {
    category_path: CategoryPath,
    name: String,
    length: i32,
    description: String,
    settings: SharedSettings,
    /// Name/value pairs in the order `DataTypesSarifMgr` supplied them.
    pub values: Vec<(String, i64)>,
}

impl EnumDataType {
    /// `new EnumDataType(CategoryPath path, String name, int length, DataTypeManager dtm)`.
    pub fn new(category_path: CategoryPath, name: &str, length: i32) -> Self {
        Self {
            category_path,
            name: name.to_string(),
            length,
            description: String::new(),
            settings: SharedSettings::new(),
            values: Vec::new(),
        }
    }

    /// `Enum.add(String name, long value, String comment)`; `DataTypesSarifMgr` always passes a
    /// `null` comment, so none is recorded.
    pub fn add(&mut self, name: &str, value: i64) {
        self.values.push((name.to_string(), value));
    }
}

impl CompositePacking for EnumDataType {}

impl DataType for EnumDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        self.category_path = path;
        Ok(())
    }

    fn get_description(&self) -> String {
        self.description.clone()
    }

    fn set_description(
        &mut self,
        description: &str,
    ) -> Result<(), crate::program::model::data::data_type::UnsupportedOperationError> {
        self.description = description.to_string();
        Ok(())
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }
}

/// Placeholder for `ghidra.program.model.data.TypedefDataType`'s
/// `TypedefDataType(CategoryPath, String, DataType, DataTypeManager)` constructor. See
/// [`StructureDataType`].
#[derive(Clone)]
pub struct TypedefDataType {
    category_path: CategoryPath,
    name: String,
    settings: SharedSettings,
    pub base_data_type: Arc<dyn DataType>,
    pub auto_named: bool,
}

impl TypedefDataType {
    /// `new TypedefDataType(CategoryPath path, String name, DataType dt, DataTypeManager dtm)`.
    pub fn new(category_path: CategoryPath, name: &str, base_data_type: Arc<dyn DataType>) -> Self {
        Self {
            category_path,
            name: name.to_string(),
            settings: SharedSettings::new(),
            base_data_type,
            auto_named: false,
        }
    }

    /// `TypeDef.enableAutoNaming()`.
    pub fn enable_auto_naming(&mut self) {
        self.auto_named = true;
    }
}

impl CompositePacking for TypedefDataType {}

impl DataType for TypedefDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_length(&self) -> i32 {
        self.base_data_type.get_length()
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        self.category_path = path;
        Ok(())
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }

    fn is_typedef(&self) -> bool {
        true
    }
}

/// Placeholder for `ghidra.program.model.data.PointerDataType`'s
/// `PointerDataType(DataType, DataTypeManager)` and `PointerDataType(DataType, int,
/// DataTypeManager)` constructors. See [`StructureDataType`].
#[derive(Clone)]
pub struct PointerDataType {
    length: i32,
    settings: SharedSettings,
    pub base_data_type: Arc<dyn DataType>,
}

impl PointerDataType {
    /// `new PointerDataType(DataType dt, DataTypeManager dtm)`. The pointer size comes from the
    /// data organization in Java; with no manager here the length is reported as unknown (`-1`).
    pub fn new(base_data_type: Arc<dyn DataType>) -> Self {
        Self {
            length: -1,
            settings: SharedSettings::new(),
            base_data_type,
        }
    }

    /// `new PointerDataType(DataType dt, int length, DataTypeManager dtm)`.
    pub fn with_size(base_data_type: Arc<dyn DataType>, length: i32) -> Self {
        Self {
            length,
            settings: SharedSettings::new(),
            base_data_type,
        }
    }
}

impl CompositePacking for PointerDataType {}

impl DataType for PointerDataType {
    /// `PointerDataType.getName()`, which is the pointed-to type's name followed by `" *"`.
    fn get_name(&self) -> String {
        format!("{} *", self.base_data_type.get_name())
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_category_path(&self) -> CategoryPath {
        self.base_data_type.get_category_path()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }

    fn is_pointer(&self) -> bool {
        true
    }
}

/// Placeholder for `ghidra.program.model.data.ArrayDataType`'s
/// `ArrayDataType(DataType, int, int, DataTypeManager)` constructor. See [`StructureDataType`].
#[derive(Clone)]
pub struct ArrayDataType {
    settings: SharedSettings,
    pub base_data_type: Arc<dyn DataType>,
    pub num_elements: i32,
    pub element_length: i32,
}

impl ArrayDataType {
    /// `new ArrayDataType(DataType dt, int numElements, int elementLength, DataTypeManager dtm)`.
    pub fn new(base_data_type: Arc<dyn DataType>, num_elements: i32, element_length: i32) -> Self {
        Self {
            settings: SharedSettings::new(),
            base_data_type,
            num_elements,
            element_length,
        }
    }
}

impl CompositePacking for ArrayDataType {}

impl DataType for ArrayDataType {
    /// `ArrayDataType.getName()`, which is the element type's name followed by `[n]`.
    fn get_name(&self) -> String {
        format!("{}[{}]", self.base_data_type.get_name(), self.num_elements)
    }

    fn get_length(&self) -> i32 {
        self.num_elements * self.element_length
    }

    fn get_category_path(&self) -> CategoryPath {
        self.base_data_type.get_category_path()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }

    fn is_array(&self) -> bool {
        true
    }
}

/// One argument recorded by [`FunctionDefinitionDataType::replace_argument`].
#[derive(Clone)]
pub struct PlaceholderParameterDefinition {
    pub ordinal: i32,
    pub name: Option<String>,
    pub data_type: Arc<dyn DataType>,
    pub comment: Option<String>,
    pub source: SourceType,
}

/// Placeholder for `ghidra.program.model.data.FunctionDefinitionDataType`'s
/// `FunctionDefinitionDataType(CategoryPath, String, DataTypeManager)` constructor. See
/// [`StructureDataType`].
#[derive(Clone)]
pub struct FunctionDefinitionDataType {
    category_path: CategoryPath,
    name: String,
    settings: SharedSettings,
    pub return_type: Option<Arc<dyn DataType>>,
    pub arguments: Vec<PlaceholderParameterDefinition>,
    pub var_args: bool,
    pub no_return: bool,
    pub calling_convention_name: Option<String>,
}

impl FunctionDefinitionDataType {
    /// `new FunctionDefinitionDataType(CategoryPath path, String name, DataTypeManager dtm)`.
    pub fn new(category_path: CategoryPath, name: &str) -> Self {
        Self {
            category_path,
            name: name.to_string(),
            settings: SharedSettings::new(),
            return_type: None,
            arguments: Vec::new(),
            var_args: false,
            no_return: false,
            calling_convention_name: None,
        }
    }

    /// `FunctionDefinition.setVarArgs(boolean)`.
    pub fn set_var_args(&mut self, var_args: bool) {
        self.var_args = var_args;
    }

    /// `FunctionDefinition.setNoReturn(boolean)`.
    pub fn set_no_return(&mut self, no_return: bool) {
        self.no_return = no_return;
    }

    /// `FunctionDefinition.setCallingConvention(String)`.
    pub fn set_calling_convention(&mut self, name: Option<String>) {
        self.calling_convention_name = name;
    }

    /// `FunctionDefinition.setReturnType(DataType)`.
    pub fn set_return_type(&mut self, return_type: Arc<dyn DataType>) {
        self.return_type = Some(return_type);
    }

    /// `FunctionDefinition.replaceArgument(int ordinal, String name, DataType, String comment,
    /// SourceType)`.
    pub fn replace_argument(
        &mut self,
        ordinal: i32,
        name: Option<String>,
        data_type: Arc<dyn DataType>,
        comment: Option<String>,
        source: SourceType,
    ) {
        let replacement = PlaceholderParameterDefinition {
            ordinal,
            name,
            data_type,
            comment,
            source,
        };
        match self.arguments.iter_mut().find(|a| a.ordinal == ordinal) {
            Some(existing) => *existing = replacement,
            None => self.arguments.push(replacement),
        }
    }
}

impl CompositePacking for FunctionDefinitionDataType {}

impl DataType for FunctionDefinitionDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    /// `FunctionDefinitionDataType.getLength()` is always 1.
    fn get_length(&self) -> i32 {
        1
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        self.category_path = path;
        Ok(())
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(self.settings.clone())
    }

    fn is_function_definition_type(&self) -> bool {
        true
    }
}

/// Placeholder for the built-in `DataType` singletons `DataTypesSarifMgr.foreignTypedefs` maps
/// onto (`CharDataType.dataType`, `PascalString255DataType.dataType`, ...). Each of those classes
/// is a trait in the crate with no constructible instance yet, so this carries just the name and
/// length the manager's lookups depend on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltInDataTypePlaceholder {
    name: String,
    length: i32,
}

impl BuiltInDataTypePlaceholder {
    /// A built-in of the given Ghidra name and length (`-1` for the dynamically-sized strings).
    pub fn new(name: &str, length: i32) -> Self {
        Self {
            name: name.to_string(),
            length,
        }
    }
}

impl DataType for BuiltInDataTypePlaceholder {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_length(&self) -> i32 {
        self.length
    }
}

/// Placeholder for `sarif.managers.DtParser`, which resolves a data type by name against a
/// `DataTypeManager` (via `DataTypeParser`). Neither class is ported yet, so this always reports
/// "not found" -- the same answer Java gives for a name the manager does not know.
pub struct DtParser;

impl DtParser {
    /// `new DtParser(DataTypeManager dtm)`, minus the manager it would search.
    pub fn new() -> Self {
        DtParser
    }

    /// `DtParser.parseDataType(String dtName, CategoryPath category, int size)`.
    pub fn parse_data_type(
        &self,
        _name: &str,
        _category: &CategoryPath,
        _size: i32,
    ) -> Option<Arc<dyn DataType>> {
        None
    }
}

impl Default for DtParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder for `sarif.export.data.SarifDataTypeWriter`, referenced by
/// [`DataTypesSarifMgr::write_as_sarif`](crate::sarif::managers::DataTypesSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled; the `genRoot`/`AbstractExtWriter` machinery that turns the data types
/// into SARIF JSON is pending that class's own port.
pub struct SarifDataTypeWriter {
    pub data_types: Vec<Box<dyn DataType>>,
}

impl SarifDataTypeWriter {
    /// `new SarifDataTypeWriter(DataTypeManager dtm, List<DataType> target, Writer baseWriter)`,
    /// minus the manager and the (always `null`, here) base writer.
    pub fn new(data_types: Vec<Box<dyn DataType>>) -> Self {
        Self { data_types }
    }
}

/// Placeholder for `sarif.managers.ProgramSarifMgr`, referenced by
/// [`MemoryMapSarifMgr`](crate::sarif::managers::MemoryMapSarifMgr) (a forward reference: it sits
/// on the read/write cycle between a per-section manager like `MemoryMapSarifMgr` and the
/// `ProgramSarifMgr` that owns it). Java's version is a concrete class, not an interface, so this
/// is a plain struct. Only the member `MemoryMapSarifMgr` reads through it -- the import
/// directory a `MEMORY_MAP` block's file-backed contents are read from -- is modeled.
pub struct ProgramSarifMgr {
    directory: String,
}

impl ProgramSarifMgr {
    /// `new ProgramSarifMgr(Program program, MessageLog log)`, minus the program/log fields
    /// (this placeholder stands in for the directory accessor only).
    pub fn new(directory: impl Into<String>) -> Self {
        Self { directory: directory.into() }
    }

    /// `ProgramSarifMgr.getDirectory()`.
    pub fn get_directory(&self) -> &str {
        &self.directory
    }
}

/// Placeholder for `sarif.SarifUtils`, referenced by
/// [`MemoryMapSarifMgr::process_memory_block`](crate::sarif::managers::MemoryMapSarifMgr). Java's
/// version is a class of static methods backed by SARIF's own `Location`/`PhysicalLocation`
/// object model (none of which are ported), so this is a statics holder too. Only
/// `getLocations(Map<String, Object>, Program, AddressSet)` is modeled; since the `"Locations"`
/// list it would walk cannot be read yet, it always hands back the `set` it was given (or a fresh
/// empty one), the same as Java does for a result with no `"Locations"` entry.
pub struct SarifUtils;

impl SarifUtils {
    /// `SarifUtils.getLocations(Map<String, Object>, Program, AddressSet)`.
    pub fn get_locations(
        _result: &HashMap<String, serde_json::Value>,
        _program: &dyn Program,
        set: Option<AddressSet>,
    ) -> Result<AddressSet, AddressOverflowException> {
        Ok(set.unwrap_or_default())
    }
}

/// Placeholder for `ghidra.app.util.MemoryBlockUtils`, referenced by
/// [`MemoryMapSarifMgr::process_memory_block`](crate::sarif::managers::MemoryMapSarifMgr). Java's
/// version is a class of static methods that create memory blocks through `Memory`'s
/// `create*Block` family; the ported [`Memory`](crate::program::model::mem::Memory) trait only
/// has [`create_initialized_block`](crate::program::model::mem::Memory::create_initialized_block)
/// so far (a fixed-fill-byte block, not one backed by arbitrary bytes or another block's address
/// range), so none of the block-creation calls below can actually create a block yet. Each
/// method mirrors Java's "operation failed" `null` return -- logging the same message Java's own
/// `catch (Exception e)` clause would -- rather than faking a partial creation the real class
/// does not offer.
pub struct MemoryBlockUtils;

impl MemoryBlockUtils {
    /// `MemoryBlockUtils.createUninitializedBlock(Program, boolean, String, Address, long,
    /// String, String, boolean, boolean, boolean, MessageLog)`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_uninitialized_block(
        _program: &dyn Program,
        _is_overlay: bool,
        name: &str,
        _start: &Address,
        _length: i64,
        _comment: Option<&str>,
        _source: Option<&str>,
        _r: bool,
        _w: bool,
        _x: bool,
        log: &MessageLog,
    ) -> Option<Arc<dyn MemoryBlock>> {
        log.append_msg(format!(
            "Failed to create '{name}' memory block: block creation is not supported yet"
        ));
        None
    }

    /// `MemoryBlockUtils.createInitializedBlock(Program, boolean, String, Address, InputStream,
    /// long, String, String, boolean, boolean, boolean, MessageLog, TaskMonitor)`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_initialized_block(
        _program: &dyn Program,
        _is_overlay: bool,
        name: &str,
        _start: &Address,
        _data: &[u8],
        _comment: Option<&str>,
        _source: Option<&str>,
        _r: bool,
        _w: bool,
        _x: bool,
        log: &MessageLog,
        _monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn MemoryBlock>> {
        log.append_msg(format!(
            "Failed to create '{name}' memory block: block creation is not supported yet"
        ));
        None
    }

    /// `MemoryBlockUtils.createBitMappedBlock(Program, String, Address, Address, int, String,
    /// String, boolean, boolean, boolean, boolean, MessageLog)`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_bit_mapped_block(
        _program: &dyn Program,
        name: &str,
        _start: &Address,
        _base: Option<&Address>,
        _length: i32,
        _comment: Option<&str>,
        _source: Option<&str>,
        _r: bool,
        _w: bool,
        _x: bool,
        _overlay: bool,
        log: &MessageLog,
    ) -> Option<Arc<dyn MemoryBlock>> {
        log.append_msg(format!(
            "Failed to create '{name}' mapped memory block: block creation is not supported yet"
        ));
        None
    }

    /// `MemoryBlockUtils.createByteMappedBlock(Program, String, Address, Address, int, String,
    /// String, boolean, boolean, boolean, boolean, MessageLog)`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_byte_mapped_block(
        _program: &dyn Program,
        name: &str,
        _start: &Address,
        _base: Option<&Address>,
        _length: i32,
        _comment: Option<&str>,
        _source: Option<&str>,
        _r: bool,
        _w: bool,
        _x: bool,
        _overlay: bool,
        log: &MessageLog,
    ) -> Option<Arc<dyn MemoryBlock>> {
        log.append_msg(format!(
            "Failed to create '{name}' mapped memory block: block creation is not supported yet"
        ));
        None
    }
}

/// Placeholder for `sarif.export.registers.SarifRegisterValueWriter`, referenced by
/// [`RegisterValuesSarifMgr::write_as_sarif`](crate::sarif::managers::RegisterValuesSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// register list and address ranges are modeled; the `ProgramContext` collaborator (needed to
/// read register values back out for each range) and the `genRoot`/`AbstractExtWriter` machinery
/// that turns them into SARIF JSON are pending that class's own port.
pub struct SarifRegisterValueWriter {
    pub registers: Vec<crate::program::model::lang::register::RegisterRef>,
    pub ranges: Vec<AddressRange>,
}

impl SarifRegisterValueWriter {
    /// `new SarifRegisterValueWriter(ProgramContext context, List<Register> registers,
    /// List<AddressRange> request, Writer baseWriter)`, minus the context (pending its own use
    /// here) and the (always `null`, here) base writer.
    pub fn new(registers: Vec<crate::program::model::lang::register::RegisterRef>, ranges: Vec<AddressRange>) -> Self {
        Self { registers, ranges }
    }
}

/// Placeholder for `sarif.export.mm.SarifMemoryMapWriter`, referenced by
/// [`MemoryMapSarifMgr::write_as_sarif`](crate::sarif::managers::MemoryMapSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor's request list and write-contents flag are modeled; the `bytesFile` collaborator
/// (kept by the caller instead, see
/// [`MemoryMapSarifMgr::write`](crate::sarif::managers::MemoryMapSarifMgr::write)) and the
/// `genRoot`/`AbstractExtWriter` machinery that turns the request into SARIF JSON are pending that
/// class's own port.
pub struct SarifMemoryMapWriter {
    pub memory: Vec<(AddressRange, Arc<dyn MemoryBlock>)>,
    pub write_contents: bool,
}

impl SarifMemoryMapWriter {
    /// `new SarifMemoryMapWriter(List<Pair<AddressRange, MemoryBlock>> request, Writer baseWriter,
    /// MemoryMapBytesFile bytes, boolean isWriteContents)`, minus the (always `null`, here) base
    /// writer and the bytes file.
    pub fn new(memory: Vec<(AddressRange, Arc<dyn MemoryBlock>)>, write_contents: bool) -> Self {
        Self { memory, write_contents }
    }
}
