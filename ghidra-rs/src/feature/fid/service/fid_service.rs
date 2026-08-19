use std::collections::HashMap;
use std::sync::Arc;

use crate::feature::fid::db::fid_db::FidDB;
use crate::feature::fid::db::fid_query_service::FidQueryService;
use crate::feature::fid::db::function_record::FunctionRecord;
use crate::feature::fid::db::library_record::LibraryRecord;
use crate::feature::fid::hash::{FidHashQuad, FidHasher, FunctionExtentGenerator};
use crate::feature::seam_stubs::{
    FidFileManager, FidPopulateResult, FidProgramSeeker, FidSearchResult, FidServiceLibraryIngest,
    FunctionBodyFunctionExtentGenerator, GetFidDbError, MessageDigestFidHasher,
};
use crate::framework::model::DomainFile;
use crate::generic::hash::{FNV1a64MessageDigestFactory, MessageDigestFactory};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::listing::{Function, Program};
use crate::program::model::mem::MemoryAccessException;
use crate::util::exception::{CancelledException, VersionException};
use crate::util::search::instruction_skipper::InstructionSkipper;
use crate::util::task::TaskMonitor;

/// The length (in code units) of the short hash.
///
/// Java: `FidService.SHORT_HASH_CODE_UNIT_LENGTH`.
pub const SHORT_HASH_CODE_UNIT_LENGTH: i8 = 4;

/// The length limit (in code units) of the medium hash.
///
/// Java: `FidService.MEDIUM_HASH_CODE_UNIT_LENGTH`.
pub const MEDIUM_HASH_CODE_UNIT_LENGTH: i8 = 24;

/// The default threshold for a code unit score to be considered a match.
///
/// Java: `FidService.SCORE_THRESHOLD`.
pub const SCORE_THRESHOLD: f32 = 14.6;

/// The default code unit threshold for labeling a function with conflicting matches.
///
/// Java: `FidService.MULTINAME_SCORE_THRESHOLD`.
pub const MULTINAME_SCORE_THRESHOLD: f32 = 30.0;

/// Combines the checked exceptions `FidService.processProgram` declares.
#[derive(thiserror::Error, Debug)]
pub enum ProcessProgramError {
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<GetFidDbError> for ProcessProgramError {
    fn from(err: GetFidDbError) -> Self {
        match err {
            GetFidDbError::Version(e) => Self::Version(e),
            GetFidDbError::Io(e) => Self::Io(e),
        }
    }
}

/// Combines the checked exceptions `FidService.createNewLibraryFromPrograms` declares.
#[derive(thiserror::Error, Debug)]
pub enum CreateLibraryError {
    #[error(transparent)]
    MemoryAccess(#[from] MemoryAccessException),
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    /// Java: `IllegalStateException`, raised when the ingest finds the library in an
    /// unusable state.
    #[error("illegal state: {0}")]
    IllegalState(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Implementation of the easy parts of the FID service; the complicated methods all delegate to
/// the `*LibraryCreation` or `*LibrarySearch` utility types.
///
/// Port of `ghidra.feature.fid.service.FidService`.
///
/// Java's constructor discovers every `InstructionSkipper` through `ClassSearcher` and obtains
/// the `FidFileManager` singleton through `getInstance()`. Neither has a Rust counterpart yet, so
/// both are supplied to [`FidService::new`] instead; the grouping of the skippers by processor,
/// and everything downstream of it, matches Java exactly.
pub struct FidService {
    fid_file_manager: Arc<dyn FidFileManager>,
    generator: Arc<dyn FunctionExtentGenerator + Send + Sync>,
    digest_factory: Arc<dyn MessageDigestFactory + Send + Sync>,
    /// Java keys this map by `Processor`, whose identity is its name; the name is the key here.
    skippers: HashMap<String, Vec<Arc<dyn InstructionSkipper + Send + Sync>>>,
}

impl FidService {
    /// Creates a service over the given file manager, bucketing `skippers` by the processor each
    /// one applies to (Java does this over the `ClassSearcher` results).
    pub fn new(
        fid_file_manager: Arc<dyn FidFileManager>,
        skippers: Vec<Arc<dyn InstructionSkipper + Send + Sync>>,
    ) -> Self {
        Self::with_components(
            fid_file_manager,
            Arc::new(FunctionBodyFunctionExtentGenerator),
            Arc::new(FNV1a64MessageDigestFactory),
            skippers,
        )
    }

    /// Creates a service with an explicit extent generator and digest factory, which Java's
    /// constructor hard-codes to `FunctionBodyFunctionExtentGenerator` and
    /// `FNV1a64MessageDigestFactory`.
    pub fn with_components(
        fid_file_manager: Arc<dyn FidFileManager>,
        generator: Arc<dyn FunctionExtentGenerator + Send + Sync>,
        digest_factory: Arc<dyn MessageDigestFactory + Send + Sync>,
        skippers: Vec<Arc<dyn InstructionSkipper + Send + Sync>>,
    ) -> Self {
        let mut by_processor: HashMap<String, Vec<Arc<dyn InstructionSkipper + Send + Sync>>> =
            HashMap::new();
        for skipper in skippers {
            let processor = skipper.get_applicable_processor().name();
            by_processor.entry(processor).or_default().push(skipper);
        }
        Self { fid_file_manager, generator, digest_factory, skippers: by_processor }
    }

    /// Returns the length (in code units) of the short hash.
    pub fn short_hash_code_unit_length(&self) -> i8 {
        SHORT_HASH_CODE_UNIT_LENGTH
    }

    /// Returns the length limit (in code units) of the medium hash.
    pub fn medium_hash_code_unit_length_limit(&self) -> i8 {
        MEDIUM_HASH_CODE_UNIT_LENGTH
    }

    /// Returns the default threshold for a code unit score to be considered a match.
    pub fn default_score_threshold(&self) -> f32 {
        SCORE_THRESHOLD
    }

    /// Returns the default code unit threshold for labeling a function with conflicting matches.
    pub fn default_multi_name_threshold(&self) -> f32 {
        MULTINAME_SCORE_THRESHOLD
    }

    /// Hashes a single function, returning the small, medium and full hash result.
    ///
    /// Java returns `null` -- here [`None`] -- when the function is shorter than
    /// [`SHORT_HASH_CODE_UNIT_LENGTH`] code units, and when the hasher itself declines to hash it.
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if something goes wrong reading bytes in the domain file.
    pub fn hash_function(
        &self,
        function: &dyn Function,
    ) -> Result<Option<Arc<dyn FidHashQuad>>, MemoryAccessException> {
        let code_units = self.generator.calculate_extent(function);
        if (code_units.len() as i64) < i64::from(self.short_hash_code_unit_length()) {
            return Ok(None);
        }

        let program = function.get_program();
        let fid_hasher = self.get_hasher(&*program);
        fid_hasher.hash(function)
    }

    /// Returns the hasher suitable for producing [`FidHashQuad`]s for functions coming from
    /// `program`, configured with the instruction skippers registered for that program's
    /// processor (Java: `skippers.get(program.getLanguage().getProcessor())`, defaulting to an
    /// empty list).
    ///
    /// Java's return type is the `FidHasher` interface, but `MessageDigestFidHasher` is its only
    /// implementation, so the concrete hasher is returned here; coerce it to
    /// `Arc<dyn FidHasher>` where polymorphism is actually wanted.
    pub fn get_hasher(&self, program: &dyn Program) -> MessageDigestFidHasher {
        let skippers = program
            .get_language()
            .map(|language| language.get_processor().name())
            .and_then(|processor| self.skippers.get(&processor).cloned())
            .unwrap_or_default();
        MessageDigestFidHasher::new(
            Arc::clone(&self.generator),
            SHORT_HASH_CODE_UNIT_LENGTH,
            Arc::clone(&self.digest_factory),
            skippers,
        )
    }

    /// Returns the [`FidProgramSeeker`] context object for searching for FID matches in
    /// `program`, querying `fid_query_service` and reporting matches that meet `score_threshold`
    /// code units.
    pub fn get_program_seeker(
        &self,
        program: Arc<dyn Program>,
        fid_query_service: &FidQueryService,
        score_threshold: f32,
    ) -> Result<FidProgramSeeker, GetFidDbError> {
        let fid_hasher: Arc<dyn FidHasher> = Arc::new(self.get_hasher(&*program));
        FidProgramSeeker::new(
            fid_query_service,
            program,
            fid_hasher,
            self.short_hash_code_unit_length(),
            self.medium_hash_code_unit_length_limit(),
            score_threshold,
        )
    }

    /// Extracts function hashes from a list of programs (domain files) and puts them into
    /// `fid_db`.
    ///
    /// `function_filter` may reject functions from the library (Java passes a
    /// `Predicate<Pair<Function, FidHashQuad>>`), `language_id` is the Ghidra language id to
    /// filter on if any, `link_libraries` are searched for internally unresolved symbols, and no
    /// relations are generated for `common_symbols`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_new_library_from_programs(
        &self,
        fid_db: &FidDB,
        library_family_name: &str,
        library_version: &str,
        library_variant: &str,
        program_domain_files: &[Arc<dyn DomainFile>],
        function_filter: &dyn Fn(&dyn Function, &dyn FidHashQuad) -> bool,
        language_id: Option<&LanguageID>,
        link_libraries: &[LibraryRecord],
        common_symbols: &[String],
        monitor: &dyn TaskMonitor,
    ) -> Result<FidPopulateResult, CreateLibraryError> {
        let mut ingest = FidServiceLibraryIngest::new(
            fid_db,
            self,
            library_family_name,
            library_version,
            library_variant,
            program_domain_files,
            function_filter,
            language_id,
            link_libraries,
            monitor,
        );
        ingest.mark_common_child_references(common_symbols);
        Ok(ingest.create()?)
    }

    /// Searches the databases held by `query_service` for matches in `program`, reporting the
    /// matches that meet `score_threshold` code units.
    pub fn process_program(
        &self,
        program: Arc<dyn Program>,
        query_service: &FidQueryService,
        score_threshold: f32,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<FidSearchResult>, ProcessProgramError> {
        let seeker = self.get_program_seeker(program, query_service, score_threshold)?;
        Ok(seeker.search(monitor)?)
    }

    /// Marks functions as automatically passing any search, returning the records reflecting the
    /// change.
    pub fn mark_records_auto_pass(
        &self,
        func_list: &[Arc<FunctionRecord>],
        value: bool,
    ) -> std::io::Result<Vec<Arc<FunctionRecord>>> {
        let mut res = Vec::with_capacity(func_list.len());
        for func_rec in func_list {
            res.push(func_rec.get_fid_db().set_auto_pass_on_function(func_rec, value)?);
        }
        Ok(res)
    }

    /// Marks functions as automatically failing any search, returning the records reflecting the
    /// change.
    pub fn mark_records_auto_fail(
        &self,
        func_list: &[Arc<FunctionRecord>],
        value: bool,
    ) -> std::io::Result<Vec<Arc<FunctionRecord>>> {
        let mut res = Vec::with_capacity(func_list.len());
        for func_rec in func_list {
            res.push(func_rec.get_fid_db().set_auto_fail_on_function(func_rec, value)?);
        }
        Ok(res)
    }

    /// Marks functions as requiring any search result to match the specific hash, returning the
    /// records reflecting the change.
    pub fn mark_records_force_specific(
        &self,
        func_list: &[Arc<FunctionRecord>],
        value: bool,
    ) -> std::io::Result<Vec<Arc<FunctionRecord>>> {
        let mut res = Vec::with_capacity(func_list.len());
        for func_rec in func_list {
            res.push(func_rec.get_fid_db().set_force_specific_on_function(func_rec, value)?);
        }
        Ok(res)
    }

    /// Marks functions as requiring any search result to also match one of its children/parents,
    /// returning the records reflecting the change.
    pub fn mark_records_force_relation(
        &self,
        func_list: &[Arc<FunctionRecord>],
        value: bool,
    ) -> std::io::Result<Vec<Arc<FunctionRecord>>> {
        let mut res = Vec::with_capacity(func_list.len());
        for func_rec in func_list {
            res.push(func_rec.get_fid_db().set_force_relation_on_function(func_rec, value)?);
        }
        Ok(res)
    }

    /// Returns true if at least one FID library database can process programs with `language`.
    pub fn can_process(&self, language: &dyn Language) -> bool {
        self.fid_file_manager.can_query(language)
    }

    /// Creates a new [`FidQueryService`] that can perform a query over multiple FID databases.
    ///
    /// This opens the appropriate databases, so the caller is responsible for closing the
    /// returned query service when done with it. When `open_for_update` is true the databases are
    /// opened read/write, otherwise read-only.
    pub fn open_fid_query_service(
        &self,
        language: &dyn Language,
        open_for_update: bool,
    ) -> Result<FidQueryService, GetFidDbError> {
        self.fid_file_manager.open_fid_query_service(language, open_for_update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::framework::model::DomainObject;
    use crate::program::model::lang::{CompilerSpecDescription, CompilerSpecID, LanguageDescription};
    use crate::program::seam_stubs::Processor;
    use crate::util::classfinder::extension_point::ExtensionPoint;

    struct NamedProcessor(&'static str);
    impl Processor for NamedProcessor {
        fn name(&self) -> String {
            self.0.to_string()
        }
    }

    struct TestSkipper {
        processor: &'static str,
    }
    impl ExtensionPoint for TestSkipper {}
    impl InstructionSkipper for TestSkipper {
        fn get_applicable_processor(&self) -> Box<dyn Processor> {
            Box::new(NamedProcessor(self.processor))
        }

        fn should_skip(&self, buffer: &[u8]) -> bool {
            !buffer.is_empty()
        }
    }

    fn skipper(processor: &'static str) -> Arc<dyn InstructionSkipper + Send + Sync> {
        Arc::new(TestSkipper { processor })
    }

    struct MockLanguage {
        processor: &'static str,
    }
    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }

        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not needed for these tests")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>>
        {
            None
        }

        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(NamedProcessor(self.processor))
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not needed for these tests")
        }

        fn get_default_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not needed for these tests")
        }

        fn get_default_data_space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            unimplemented!("not needed for these tests")
        }

        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_instruction_alignment(&self) -> i32 {
            1
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }

        fn supports_pcode(&self) -> bool {
            true
        }

        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
            false
        }

        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not needed for these tests")
        }

        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }

        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }

        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_in_space(
            &self,
            _addrspc: &Arc<crate::program::model::address::AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_base_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }

        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }

        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            Err(
                crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException::new(
                    &self.get_language_id(),
                    compiler_spec_id,
                ),
            )
        }

        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not needed for these tests")
        }

        fn has_property(&self, _key: &str) -> bool {
            false
        }

        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }

        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }

        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }

        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }

        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn has_manual(&self) -> bool {
            false
        }

        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }

        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }

        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }

        fn get_sorted_vector_registers(
            &self,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }

        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
    }

    struct MockProgram {
        processor: &'static str,
    }
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:32:default".to_string()
        }

        fn get_language(&self) -> Option<Arc<dyn Language>> {
            Some(Arc::new(MockLanguage { processor: self.processor }))
        }
    }

    /// Records the languages `canQuery`/`openFidQueryService` were asked about, and answers
    /// `canQuery` with a fixed verdict.
    struct FakeFidFileManager {
        can_query: bool,
        queries: AtomicUsize,
    }
    impl FidFileManager for FakeFidFileManager {
        fn can_query(&self, _language: &dyn Language) -> bool {
            self.queries.fetch_add(1, Ordering::SeqCst);
            self.can_query
        }

        fn open_fid_query_service(
            &self,
            _language: &dyn Language,
            _open_for_update: bool,
        ) -> Result<FidQueryService, GetFidDbError> {
            Err(GetFidDbError::Io(std::io::Error::other("no databases installed")))
        }
    }

    fn service_with(
        can_query: bool,
        skippers: Vec<Arc<dyn InstructionSkipper + Send + Sync>>,
    ) -> (FidService, Arc<FakeFidFileManager>) {
        let manager =
            Arc::new(FakeFidFileManager { can_query, queries: AtomicUsize::new(0) });
        (FidService::new(Arc::clone(&manager) as Arc<dyn FidFileManager>, skippers), manager)
    }

    #[test]
    fn hash_lengths_and_thresholds_match_java_constants() {
        let (service, _) = service_with(false, Vec::new());

        assert_eq!(service.short_hash_code_unit_length(), 4);
        assert_eq!(service.medium_hash_code_unit_length_limit(), 24);
        assert_eq!(service.default_score_threshold(), 14.6_f32);
        assert_eq!(service.default_multi_name_threshold(), 30.0_f32);
    }

    #[test]
    fn hasher_gets_the_skippers_registered_for_the_program_processor() {
        let (service, _) = service_with(
            false,
            vec![skipper("x86"), skipper("ARM"), skipper("x86")],
        );

        let hasher = service.get_hasher(&MockProgram { processor: "x86" });

        // Java looks the skipper list up by the program's processor; the two x86 skippers apply
        // and the ARM one does not.
        assert_eq!(hasher.skippers().len(), 2);
        assert!(hasher
            .skippers()
            .iter()
            .all(|s| s.get_applicable_processor().name() == "x86"));
        assert_eq!(hasher.code_unit_threshold(), SHORT_HASH_CODE_UNIT_LENGTH);
    }

    #[test]
    fn hasher_gets_no_skippers_for_an_unregistered_processor() {
        let (service, _) = service_with(false, vec![skipper("ARM")]);

        let hasher = service.get_hasher(&MockProgram { processor: "x86" });

        assert!(hasher.skippers().is_empty());
    }

    #[test]
    fn program_seeker_is_configured_with_the_service_hash_lengths() {
        let (service, _) = service_with(false, vec![skipper("x86")]);
        let language = MockLanguage { processor: "x86" };
        let query_service = FidQueryService::new(&[], Some(&language), false)
            .expect("no fid files means nothing to open");
        let program: Arc<dyn Program> = Arc::new(MockProgram { processor: "x86" });

        let seeker = service
            .get_program_seeker(Arc::clone(&program), &query_service, 20.0)
            .expect("seeker construction");

        assert_eq!(seeker.short_hash_code_unit_length(), SHORT_HASH_CODE_UNIT_LENGTH);
        assert_eq!(
            seeker.medium_hash_code_unit_length_limit(),
            MEDIUM_HASH_CODE_UNIT_LENGTH
        );
        assert_eq!(seeker.score_threshold(), 20.0_f32);
        assert!(Arc::ptr_eq(seeker.program(), &program));
    }

    #[test]
    fn can_process_delegates_to_the_file_manager() {
        let (yes, yes_manager) = service_with(true, Vec::new());
        let (no, _) = service_with(false, Vec::new());
        let language = MockLanguage { processor: "x86" };

        assert!(yes.can_process(&language));
        assert!(!no.can_process(&language));
        assert_eq!(yes_manager.queries.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn open_fid_query_service_propagates_the_file_manager_failure() {
        let (service, _) = service_with(true, Vec::new());
        let language = MockLanguage { processor: "x86" };

        match service.open_fid_query_service(&language, false) {
            Err(GetFidDbError::Io(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("the fake manager has no databases to open"),
        }
    }

    #[test]
    fn skippers_are_grouped_by_processor_across_several_processors() {
        let (service, _) =
            service_with(false, vec![skipper("x86"), skipper("ARM"), skipper("x86")]);

        assert_eq!(service.skippers.len(), 2);
        assert_eq!(service.skippers["x86"].len(), 2);
        assert_eq!(service.skippers["ARM"].len(), 1);
    }
}
