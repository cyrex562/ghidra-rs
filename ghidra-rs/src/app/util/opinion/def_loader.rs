//! Port of `ghidra.app.util.opinion.DefLoader`.
//!
//! A [`Loader`](crate::app::util::opinion::loader::Loader) for processing Microsoft `.def`
//! (Module Definition) files: it reads the `EXPORTS` section and, for every entry with an
//! ordinal, renames the existing `Ordinal_<n>` symbol the `PE` loader already created to the
//! export's real name.
//!
//! # Departures from the Java class
//!
//! * `DefLoader extends AbstractProgramWrapperLoader` (in turn `AbstractProgramLoader`), which
//!   implement the bulk of the `Loader` interface (program creation, transaction management,
//!   `getTier()`/`getTierPriority()`, ...) and are not ported. `DefLoader.java` itself only
//!   overrides `findSupportedLoadSpecs`, `load(Program, ImporterSettings)`, `getName`, and
//!   `supportsLoadIntoProgram`, so -- like
//!   [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) and
//!   [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) -- this port models just that
//!   overridden surface as inherent methods on a standalone struct, rather than implementing the
//!   [`Loader`] trait (which would additionally require the inherited machinery this class never
//!   defines).
//! * `ByteProvider`/`DefExportLine`/`Program`/`SourceType`/`SymbolUtilities`/`InvalidInputException`
//!   are used via their real ported paths. `LoadSpec`/`QueryResult`/`PeLoader` are already-grown
//!   placeholders in [`app::seam_stubs`](crate::app::seam_stubs) (see `STUBS.tsv`); no new stub was
//!   needed for this port.
//! * `provider.getInputStream(0)` plus the `BufferedReader`/`InputStreamReader` wrapping it become
//!   a single `read_bytes(0, length)` decoded as UTF-8 and split into lines with [`str::lines`],
//!   the same "read whole file, then iterate lines" substitution
//!   [`UnixAoutProgramLoader`](crate::app::util::opinion::unix_aout_program_loader::UnixAoutProgramLoader)-style
//!   loaders use elsewhere for streaming reads the ported [`ByteProvider`] has no equivalent for.
//! * `ByteProvider.getName()` is not on the ported [`ByteProvider`] trait (only `get_fsrl`/
//!   `get_file` are). This port derives the same display name from those two instead, exactly as
//!   [`JavaLoader`]/[`XmlLoader`] do.
//! * `QueryOpinionService.query(String, String, String)` resolves the process-wide `Application`/
//!   `DefaultLanguageService` singletons; [`DefLoader::find_supported_load_specs`] threads the
//!   equivalent `&dyn Application`/`&dyn LanguageService` through explicitly instead, the same
//!   substitution `query_opinion_service::query` itself requires. Its `secondaryKey` argument is
//!   `null` in Java (`QueryOpinionService.query(getName(), NO_MAGIC, null)`); `""` is passed
//!   instead, mirroring
//!   [`DyldCacheLoader`](crate::app::util::opinion::dyld_cache_loader::DyldCacheLoader)'s identical
//!   substitution (see that module's docs for why the two are indistinguishable today).
//! * `load(Program, ImporterSettings)` takes its `ImporterSettings` fields directly as separate
//!   parameters instead of the already-ported `Loader::ImporterSettings` struct, whose `provider`
//!   field is typed as the narrower `ByteProviderLike` marker (no real byte access) and whose
//!   `log` field this method also needs to read back independently of `provider`. This mirrors
//!   [`DyldCacheLoader::load`]'s identical substitution.
//! * `SymbolUtilities.getLabelOrFunctionSymbol`/`SymbolTable.createLabel`/`Symbol.setPrimary` are
//!   ported as [`DefaultSymbolUtilities::get_label_or_function_symbol`],
//!   [`SymbolTable::create_label`](crate::program::model::symbol::SymbolTable::create_label), and
//!   [`SymbolTable::set_primary_symbol`](crate::program::model::symbol::SymbolTable::set_primary_symbol)
//!   respectively -- the last because the ported `Symbol` trait exposes no direct way to mutate a
//!   symbol handed out from behind an `Arc`, the same substitution
//!   [`AbstractOrdinalSupportLoader`](crate::app::util::opinion::abstract_ordinal_support_loader::AbstractOrdinalSupportLoader)'s
//!   `applyLibrarySymbols` already made.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::app::seam_stubs::{LoadSpec, MessageLog, PeLoader};
use crate::app::util::opinion::def_export_line::DefExportLine;
use crate::app::util::opinion::query_opinion_service;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::framework::application::Application;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{DefaultSymbolUtilities, SourceType, SymbolUtilities, ORDINAL_PREFIX};

/// `DefLoader.DEF_NAME`.
pub const DEF_NAME: &str = "Module Definition (DEF)";

/// `DefLoader.NO_MAGIC`.
pub const NO_MAGIC: &str = "0";

/// A [`Loader`] for processing Microsoft DEF files.
///
/// Port of `ghidra.app.util.opinion.DefLoader`; see the module docs for why this is a standalone
/// struct rather than an implementor of the [`Loader`] trait.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefLoader;

impl DefLoader {
    pub fn new() -> Self {
        DefLoader
    }

    /// `DefLoader.parseExports(ByteProvider)`.
    fn parse_exports(provider: &Rc<RefCell<dyn ByteProvider>>) -> io::Result<Vec<DefExportLine>> {
        let mut list = Vec::new();

        let bytes = {
            let mut borrowed = provider.borrow_mut();
            let length = borrowed.length()?;
            borrowed.read_bytes(0, length as usize)?
        };
        let text = String::from_utf8_lossy(&bytes);

        let mut has_exports = false;
        for line in text.lines() {
            if line.starts_with(';') || line.is_empty() {
                // comment
                continue;
            } else if line.starts_with("LIBRARY") {
                // why skip libraries?  Who knows?  If you do, please update this comment
            } else if line.starts_with("EXPORTS") {
                has_exports = true;
            } else if has_exports {
                list.push(DefExportLine::new(line)?);
            }
        }

        Ok(list)
    }

    /// `DefLoader.findSupportedLoadSpecs(ByteProvider)`. See the module docs for why the
    /// application/language service are passed in.
    pub fn find_supported_load_specs(
        &self,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        app: &dyn Application,
        language_service: &dyn LanguageService,
    ) -> io::Result<Vec<LoadSpec>> {
        let mut load_specs = Vec::new();

        let name = Self::provider_name(provider);
        if name.to_lowercase().ends_with(".def") && !Self::parse_exports(provider)?.is_empty() {
            let results =
                query_opinion_service::query(app, language_service, self.get_name(), NO_MAGIC, "");
            for result in &results {
                load_specs.push(LoadSpec::from_query_result(0, result));
            }
            if load_specs.is_empty() {
                load_specs.push(LoadSpec::without_language_compiler_spec(0, true));
            }
        }

        Ok(load_specs)
    }

    /// `DefLoader.load(Program, ImporterSettings)`. See the module docs for why the
    /// `ImporterSettings` fields are passed in individually.
    ///
    /// # Errors
    /// Returns `Err` if `program`'s executable format is not [`PeLoader::PE_NAME`], or if reading
    /// `provider`'s bytes fails.
    pub fn load(
        &self,
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        log: &dyn MessageLog,
    ) -> io::Result<()> {
        if program.get_executable_format() != PeLoader::PE_NAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Program must be a {}", PeLoader::PE_NAME),
            ));
        }

        let mut error_consumer = |err: String| log.append_msg_from("DefLoader", &err);

        for def in Self::parse_exports(provider)? {
            let Some(ordinal) = def.ordinal() else {
                continue;
            };

            let ordinal_name = format!("{ORDINAL_PREFIX}{ordinal}");
            let Some(symbol) = DefaultSymbolUtilities.get_label_or_function_symbol(
                program,
                &ordinal_name,
                &mut error_consumer,
            ) else {
                continue;
            };

            let Some(symbol_table) = program.get_symbol_table() else {
                continue;
            };
            match symbol_table.create_label(&symbol.get_address(), def.name(), SourceType::Imported) {
                Ok(label) => {
                    if let Err(e) = symbol_table.set_primary_symbol(label.get_id()) {
                        log.append_msg(&e.to_string());
                    }
                }
                Err(e) => log.append_msg(&e.to_string()),
            }
        }

        Ok(())
    }

    /// `DefLoader.getName()`.
    pub fn get_name(&self) -> &'static str {
        DEF_NAME
    }

    /// `DefLoader.supportsLoadIntoProgram(Program)`.
    pub fn supports_load_into_program(&self, _program: &dyn Program) -> bool {
        true
    }

    /// Stands in for `provider.getName()`, which is not on the ported [`ByteProvider`] trait. See
    /// the module docs.
    fn provider_name(provider: &Rc<RefCell<dyn ByteProvider>>) -> String {
        let borrowed = provider.borrow();
        if let Some(name) = borrowed.get_fsrl().and_then(|f| f.name()) {
            return name;
        }
        if let Some(path) = borrowed.get_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                return name.to_string();
            }
        }
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::application_properties::ApplicationProperties;
    use crate::framework::model::DomainObject;
    use crate::framework::platform::Platform;
    use crate::framework::seam_stubs::ApplicationLayoutLike;
    use crate::generic::jar::ResourceFile;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::symbol::{Symbol, SymbolTable, SymbolType};
    use crate::program::seam_stubs::LanguageNotFoundException;
    use std::sync::Arc;

    fn provider(data: &[u8], name: &str) -> Rc<RefCell<dyn ByteProvider>> {
        struct FakeByteProvider {
            data: Vec<u8>,
            name: String,
        }

        impl ByteProvider for FakeByteProvider {
            fn length(&mut self) -> io::Result<u64> {
                Ok(self.data.len() as u64)
            }

            fn is_valid_index(&mut self, index: u64) -> bool {
                index < self.data.len() as u64
            }

            fn read_byte(&mut self, index: u64) -> io::Result<u8> {
                self.data
                    .get(index as usize)
                    .copied()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
            }

            fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
                let start = index as usize;
                let end = start + length;
                if end > self.data.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough data"));
                }
                Ok(self.data[start..end].to_vec())
            }

            fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
                unimplemented!("not exercised by this smoke test")
            }

            fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
                unimplemented!("not exercised by this smoke test")
            }

            fn get_file(&self) -> Option<std::path::PathBuf> {
                Some(std::path::PathBuf::from(&self.name))
            }
        }

        Rc::new(RefCell::new(FakeByteProvider { data: data.to_vec(), name: name.to_string() }))
    }

    /// An [`Application`] that reports no `.opinion` files, matching
    /// [`DyldCacheLoader`](crate::app::util::opinion::dyld_cache_loader::DyldCacheLoader)'s
    /// `EmptyApplication` test double: `ApplicationLayoutLike::modules` defaults to empty.
    struct EmptyApplication;

    impl ApplicationLayoutLike for EmptyApplication {
        fn application_properties(&self) -> &dyn ApplicationProperties {
            unimplemented!("not exercised by this smoke test")
        }
        fn application_installation_dir(&self) -> Option<&ResourceFile> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl Application for EmptyApplication {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            Box::new(EmptyApplication)
        }
        fn current_platform(&self) -> Box<dyn Platform> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A `LanguageService` never actually called: with zero `.opinion` files found, the opinion
    /// database this loader queries is always empty, so `query_opinion_service` never has a
    /// language/compiler-spec pair to expand a query against.
    struct UnusedLanguageService;

    impl LanguageService for UnusedLanguageService {
        fn get_language(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_language(
            &self,
            _processor: &dyn crate::program::seam_stubs::Processor,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language_description(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn LanguageDescription>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language_descriptions(
            &self,
            _include_deprecated_languages: bool,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
        fn get_language_descriptions_matching(
            &self,
            _processor: &dyn crate::program::seam_stubs::Processor,
            _endianness: Option<Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
        fn get_language_compiler_spec_pairs(
            &self,
            _query: &crate::program::seam_stubs::LanguageCompilerSpecQuery,
        ) -> Vec<crate::program::seam_stubs::LanguageCompilerSpecPair> {
            Vec::new()
        }
        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &crate::program::seam_stubs::ExternalLanguageCompilerSpecQuery,
        ) -> Vec<crate::program::seam_stubs::LanguageCompilerSpecPair> {
            Vec::new()
        }
        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn crate::program::seam_stubs::Processor,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
    }

    #[test]
    fn constants_match_java() {
        assert_eq!(DEF_NAME, "Module Definition (DEF)");
        assert_eq!(NO_MAGIC, "0");
    }

    #[test]
    fn get_name_returns_def_name() {
        assert_eq!(DefLoader.get_name(), DEF_NAME);
    }

    #[test]
    fn supports_load_into_program_is_true() {
        struct DummyProgram;
        impl DomainObject for DummyProgram {}
        impl Program for DummyProgram {
            fn get_name(&self) -> String {
                "dummy".to_string()
            }
            fn get_language_id(&self) -> String {
                "dummy:LE:32:default".to_string()
            }
        }
        assert!(DefLoader.supports_load_into_program(&DummyProgram));
    }

    #[test]
    fn find_supported_load_specs_empty_for_non_def_name() {
        let p = provider(b"EXPORTS\nfoo @1\n", "library.dll");
        let specs =
            DefLoader.find_supported_load_specs(&p, &EmptyApplication, &UnusedLanguageService).unwrap();
        assert!(specs.is_empty());
    }

    #[test]
    fn find_supported_load_specs_empty_when_no_exports_section() {
        let p = provider(b"LIBRARY foo\n", "library.def");
        let specs =
            DefLoader.find_supported_load_specs(&p, &EmptyApplication, &UnusedLanguageService).unwrap();
        assert!(specs.is_empty());
    }

    #[test]
    fn find_supported_load_specs_falls_back_to_incomplete_spec_for_valid_def() {
        // With no `.opinion` files registered (see `UnusedLanguageService`'s docs),
        // `QueryOpinionService.query` always returns no results, so this exercises Java's
        // `if (loadSpecs.isEmpty()) { loadSpecs.add(new LoadSpec(this, 0, true)); }` fallback.
        let p = provider(b"EXPORTS\nfoo @1\nbar @2\n", "library.DEF");
        let specs =
            DefLoader.find_supported_load_specs(&p, &EmptyApplication, &UnusedLanguageService).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].desired_image_base, 0);
        assert!(specs[0].requires_language_compiler_spec);
        assert!(!specs[0].preferred);
        assert!(specs[0].language_compiler_spec.is_none());
    }

    struct MockSymbol {
        address: Address,
        name: String,
        id: i64,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockSymbolTable {
        ordinal_symbols: Vec<Arc<dyn Symbol>>,
        created_labels: Vec<(Address, String)>,
        primary_ids: Vec<i64>,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            addr: &Address,
            name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            self.created_labels.push((addr.clone(), name.to_string()));
            let symbol: Arc<dyn Symbol> =
                Arc::new(MockSymbol { address: addr.clone(), name: name.to_string(), id: 100 });
            Ok(symbol)
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.ordinal_symbols.iter().filter(|s| s.get_address() == *addr).cloned().collect())
        }
        fn get_label_or_function_symbols(&self, name: &str) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.ordinal_symbols.iter().filter(|s| s.get_name() == name).cloned().collect())
        }
        fn set_primary_symbol(&mut self, symbol_id: i64) -> io::Result<bool> {
            self.primary_ids.push(symbol_id);
            Ok(true)
        }
    }

    struct MockProgram {
        format: String,
        symbol_table: MockSymbolTable,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_executable_format(&self) -> String {
            self.format.clone()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.symbol_table)
        }
    }

    fn ram_address(offset: i64) -> Address {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1).address(offset)
    }

    #[test]
    fn load_rejects_non_pe_program() {
        let mut program = MockProgram {
            format: "Not PE".to_string(),
            symbol_table: MockSymbolTable {
                ordinal_symbols: Vec::new(),
                created_labels: Vec::new(),
                primary_ids: Vec::new(),
            },
        };
        struct NoopLog;
        impl MessageLog for NoopLog {}

        let p = provider(b"EXPORTS\nfoo @1\n", "library.def");
        let err = DefLoader.load(&mut program, &p, &NoopLog).unwrap_err();
        assert!(err.to_string().contains(PeLoader::PE_NAME));
    }

    #[test]
    fn load_renames_ordinal_symbol_and_sets_primary() {
        let ordinal_symbol: Arc<dyn Symbol> = Arc::new(MockSymbol {
            address: ram_address(0x1000),
            name: format!("{ORDINAL_PREFIX}1"),
            id: 7,
        });
        let mut program = MockProgram {
            format: PeLoader::PE_NAME.to_string(),
            symbol_table: MockSymbolTable {
                ordinal_symbols: vec![ordinal_symbol],
                created_labels: Vec::new(),
                primary_ids: Vec::new(),
            },
        };

        #[derive(Default)]
        struct RecordingLog {
            messages: std::sync::Mutex<Vec<String>>,
        }
        impl MessageLog for RecordingLog {
            fn append_msg(&self, message: &str) {
                self.messages.lock().unwrap().push(message.to_string());
            }
        }
        let log = RecordingLog::default();

        let p = provider(b"EXPORTS\nMyExport @1\n", "library.def");
        DefLoader.load(&mut program, &p, &log).unwrap();

        assert_eq!(
            program.symbol_table.created_labels,
            vec![(ram_address(0x1000), "MyExport".to_string())]
        );
        // `set_primary_symbol` is called with the newly created label's ID (100 per
        // `MockSymbolTable::create_label`), not the ordinal symbol's ID (7): Java's
        // `symtab.createLabel(...).setPrimary()` acts on the label it just created.
        assert_eq!(program.symbol_table.primary_ids, vec![100]);
        assert!(log.messages.lock().unwrap().is_empty());
    }

    #[test]
    fn load_skips_exports_without_ordinal() {
        let mut program = MockProgram {
            format: PeLoader::PE_NAME.to_string(),
            symbol_table: MockSymbolTable {
                ordinal_symbols: Vec::new(),
                created_labels: Vec::new(),
                primary_ids: Vec::new(),
            },
        };
        struct NoopLog;
        impl MessageLog for NoopLog {}

        let p = provider(b"EXPORTS\nNoOrdinalExport\n", "library.def");
        DefLoader.load(&mut program, &p, &NoopLog).unwrap();

        assert!(program.symbol_table.created_labels.is_empty());
        assert!(program.symbol_table.primary_ids.is_empty());
    }

    #[test]
    fn load_silently_skips_when_ordinal_symbol_is_missing() {
        // `SymbolUtilities.getLabelOrFunctionSymbol` (unlike `getExpectedLabelOrFunctionSymbol`)
        // only reports via its error consumer when *multiple* symbols match; zero matches is
        // silent, mirroring Java's `if (symbol == null) { continue; }` with no log call.
        let mut program = MockProgram {
            format: PeLoader::PE_NAME.to_string(),
            symbol_table: MockSymbolTable {
                ordinal_symbols: Vec::new(),
                created_labels: Vec::new(),
                primary_ids: Vec::new(),
            },
        };

        #[derive(Default)]
        struct RecordingLog {
            messages: std::sync::Mutex<Vec<String>>,
        }
        impl MessageLog for RecordingLog {
            fn append_msg(&self, message: &str) {
                self.messages.lock().unwrap().push(message.to_string());
            }
        }
        let log = RecordingLog::default();

        let p = provider(b"EXPORTS\nMyExport @1\n", "library.def");
        DefLoader.load(&mut program, &p, &log).unwrap();

        assert!(program.symbol_table.created_labels.is_empty());
        assert!(program.symbol_table.primary_ids.is_empty());
        assert!(log.messages.lock().unwrap().is_empty());
    }

    #[test]
    fn parse_exports_skips_comments_and_library_line_before_exports() {
        let p = provider(
            b"; a comment\nLIBRARY mylib\nEXPORTS\nfoo @1\nbar\n",
            "library.def",
        );
        let exports = DefLoader::parse_exports(&p).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name(), "foo");
        assert_eq!(exports[0].ordinal(), Some(1));
        assert_eq!(exports[1].name(), "bar");
        assert!(exports[1].ordinal().is_none());
    }

    #[test]
    fn parse_exports_ignores_lines_before_exports_section() {
        let p = provider(b"foo @1\nEXPORTS\nbar @2\n", "library.def");
        let exports = DefLoader::parse_exports(&p).unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name(), "bar");
    }

    #[test]
    fn parse_exports_propagates_invalid_export_line_error() {
        let p = provider(b"EXPORTS\nfoo INVALID_TYPE\n", "library.def");
        assert!(DefLoader::parse_exports(&p).is_err());
    }
}
