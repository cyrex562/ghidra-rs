use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::app::plugin::core::checksums::md5_digest_checksum_algorithm::MD5DigestChecksumAlgorithm;
use crate::feature::bsim::query::LshException;
use crate::feature::bsim::query::description::{CategoryRecord, DescriptionManager};
use crate::feature::seam_stubs::{ExecutableRecord, FunctionTagBSimFilterType, PreFilter};
use crate::framework::application::Application;
use crate::generic::jar::resource_file::ResourceFile;
use crate::generic::seam_stubs::LSHVectorFactory;
use crate::program::model::address::Address;
use crate::program::model::lang::LanguageID;
use crate::program::model::listing::{
    Function, Program, DATE_CREATED, PROGRAM_INFO,
};
use crate::program::model::listing::library;
use crate::program::model::symbol::namespace::{Namespace, DELIMITER};
use crate::program::model::symbol::{RefType, Symbol};
use crate::util::task::TaskMonitor;

/// The date column name BSim treats as an alias for the program's creation date.
const INGEST_DATE: &str = "Ingest Date";

/// The library name used whenever a call's target cannot be attributed to a real library.
const UNKNOWN_LIBRARY: &str = "unknown";

/// Generate decompiler signatures for a set of functions.
///
/// Port of `ghidra.features.bsim.query.GenSignatures`.
///
/// # Divergences from the Java
///
/// * The program is held as `Arc<Mutex<dyn Program>>`. Java's `Program` accessors are all
///   read-only, but the ported [`Program`] trait reaches its managers through `&mut self`
///   ([`Program::get_listing`], [`Program::get_symbol_table`],
///   [`Program::get_function_manager`]), so the shared program needs interior mutability.
/// * Java caches the `FunctionManager` in a `fmanage` field. A `&mut dyn FunctionManager`
///   cannot be stored alongside the program that lends it, so the manager is fetched from the
///   program at each use instead.
/// * The inner class `SignatureTask` (and the `scanFunctions`/`scanFunction` entry points that
///   exist only to drive it, plus the `singletask`/`runningTasks` fields) are not ported: they
///   need `DecompInterface`, `DecompileOptions`, `SignatureResult` and `ParallelDecompileTask`,
///   none of which are in the crate yet. Everything those methods delegate to --
///   [`write_to_manager`](Self::write_to_manager), [`collect_calls_from_address`](Self::collect_calls_from_address),
///   [`recover_attributes`](Self::recover_attributes), [`has_body`](Self::has_body) -- is ported.
pub struct GenSignatures {
    manager: Option<DescriptionManager>,
    vector_factory: Option<Arc<LSHVectorFactory>>,
    /// Current program being analyzed.
    program: Option<Arc<Mutex<dyn Program>>>,
    exerec: Option<Arc<ExecutableRecord>>,
    /// Attributes to associate with functions.
    attributes: HashMap<String, i32>,
    /// Category types associated with executables.
    categories: Option<Vec<String>>,
    date_column_name: Option<String>,
    /// True if callgraph info should be generated along with signatures.
    gencallgraph: bool,
    is_shutdown: AtomicBool,
}

/// Info for resolving a call to a unique function in the database.
///
/// For normal functions you need the triple (executable, function name, address). For calls to
/// library (external) functions, only the library executable and the function name are needed,
/// and the address is filled in with -1.
///
/// Java: the private static nested class `GenSignatures.CallRecord`.
#[derive(Debug, Clone)]
pub struct CallRecord {
    pub exerec: Option<Arc<ExecutableRecord>>,
    pub funcname: String,
    pub address: i64,
}

impl Default for CallRecord {
    fn default() -> Self {
        Self { exerec: None, funcname: String::new(), address: 0 }
    }
}

impl GenSignatures {
    /// Prepare for generation of signature information and (possibly) callgraph information.
    ///
    /// `callgraph` is true if the caller wants callgraph information generated at the same time
    /// as signatures.
    pub fn new(callgraph: bool) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert(
            "Function ID Analyzer".to_string(),
            FunctionTagBSimFilterType::KNOWN_LIBRARY_MASK,
        );
        Self {
            manager: None,
            vector_factory: None,
            program: None,
            exerec: None,
            attributes,
            categories: None,
            date_column_name: None,
            gencallgraph: callgraph,
            is_shutdown: AtomicBool::new(false),
        }
    }

    /// True if signatures are generated together with callgraph information.
    pub fn generates_callgraph(&self) -> bool {
        self.gencallgraph
    }

    /// Record additional executable category types to collect from each program's properties.
    ///
    /// # Errors
    /// If any name contains characters a category type may not contain. Java throws
    /// `IllegalArgumentException`.
    pub fn add_executable_categories<S: AsRef<str>>(
        &mut self,
        names: &[S],
    ) -> Result<(), LshException> {
        for name in names {
            let name = name.as_ref();
            if !CategoryRecord::enforce_type_characters(name) {
                return Err(LshException::new(format!("Illegal category name: {name}")));
            }
            self.categories.get_or_insert_with(Vec::new).push(name.to_string());
        }
        Ok(())
    }

    /// Assign a distinct flag bit to each named function tag, starting just above the bits
    /// [`FunctionTagBSimFilterType`] reserves for its built-in tags.
    ///
    /// # Errors
    /// If a name contains illegal characters, or if more than
    /// [`FunctionTagBSimFilterType::MAX_TAG_COUNT`] tags are registered (Java's flag shifts off
    /// the end of the int and becomes 0). Java throws `IllegalArgumentException`.
    pub fn add_function_tags<S: AsRef<str>>(&mut self, names: &[S]) -> Result<(), LshException> {
        // The first bits are reserved.
        let mut flag: i32 = 1i32 << FunctionTagBSimFilterType::RESERVED_BITS;
        for name in names {
            let name = name.as_ref();
            if flag == 0 {
                return Err(LshException::new("Too many function tags"));
            }
            if !CategoryRecord::enforce_type_characters(name) {
                return Err(LshException::new(format!("Illegal function tag name: {name}")));
            }
            self.attributes.insert(name.to_string(), flag);
            flag = flag.wrapping_shl(1);
        }
        Ok(())
    }

    /// Establish the factory that builds feature vectors for this generator.
    ///
    /// Any signatures cached from a previous factory are dropped, since the settings they were
    /// generated under no longer apply.
    ///
    /// # Errors
    /// If the factory has no signature settings.
    pub fn set_vector_factory(
        &mut self,
        v_factory: Arc<LSHVectorFactory>,
    ) -> Result<(), LshException> {
        if v_factory.get_settings() == 0 {
            return Err(LshException::new("Cannot have signature setting of 0"));
        }
        // Java compares by reference identity; `Arc::ptr_eq` is the same test.
        if self.vector_factory.as_ref().is_some_and(|current| Arc::ptr_eq(current, &v_factory)) {
            return Ok(()); // No change to factory
        }
        if let Some(manager) = self.manager.as_mut() {
            manager.clear_functions(); // Clear out cached signatures as settings have changed
        }
        self.vector_factory = Some(v_factory);
        Ok(())
    }

    /// The factory currently building feature vectors, if one has been set.
    pub fn get_vector_factory(&self) -> Option<&Arc<LSHVectorFactory>> {
        self.vector_factory.as_ref()
    }

    /// Name the program property to read each executable's ingest date from, instead of the
    /// program's creation date.
    ///
    /// # Errors
    /// If the name contains characters a category type may not contain. Java throws
    /// `IllegalArgumentException`.
    pub fn add_date_column_name(&mut self, name: &str) -> Result<(), LshException> {
        if !CategoryRecord::enforce_type_characters(name) {
            return Err(LshException::new(format!("Illegal date column name: {name}")));
        }
        self.date_column_name = Some(name.to_string());
        Ok(())
    }

    /// The container the generated signatures accumulate in, or `None` before the first
    /// [`open_program`](Self::open_program).
    pub fn get_description_manager(&self) -> Option<&DescriptionManager> {
        self.manager.as_ref()
    }

    /// Mutable access to the accumulated signatures.
    pub fn get_description_manager_mut(&mut self) -> Option<&mut DescriptionManager> {
        self.manager.as_mut()
    }

    /// The executable record the current program was opened as.
    pub fn get_executable_record(&self) -> Option<&Arc<ExecutableRecord>> {
        self.exerec.as_ref()
    }

    /// Clear out any accumulated signatures.
    pub fn clear(&mut self) {
        if let Some(manager) = self.manager.as_mut() {
            manager.clear();
        }
        self.manager = None;
        self.program = None; // Cannot reuse unless we call open_program again
        self.exerec = None;
    }

    /// Generate an MD5 hash based just on executable metadata, for programs that were not
    /// imported from a file and so have no real hash.
    ///
    /// `nmover` is the name of the executable, `compover` and `archover` are architecture
    /// metadata. Returns the md5 result as a lower-case ascii hex string.
    fn generate_metadata_md5(nmover: &str, compover: &str, archover: &str) -> String {
        // Java walks the UTF-16 code units and narrows each to a byte with a cast.
        let mut data: Vec<u8> = Vec::new();
        for s in [nmover, compover, archover] {
            data.extend(s.encode_utf16().map(|unit| unit as u8));
        }
        let mut digester = MD5DigestChecksumAlgorithm::new();
        digester.update_checksum(&data);
        let digest = digester.checksum().expect("digest was just computed");
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Prepare to collect signatures for a new program by creating an [`ExecutableRecord`] for
    /// it in a fresh [`DescriptionManager`].
    ///
    /// `nmover`, `archover` and `compover`, when given, override the executable's name,
    /// architecture and compiler. `repo` is the repository containing the executable and `path`
    /// is the path within that repository where it can be found.
    ///
    /// # Errors
    /// If a new executable record cannot be created.
    pub fn open_program(
        &mut self,
        prog: Arc<Mutex<dyn Program>>,
        nmover: Option<&str>,
        archover: Option<&str>,
        compover: Option<&str>,
        repo: Option<&str>,
        path: Option<&str>,
    ) -> Result<(), LshException> {
        let (nmover, archover, compover, md5string) = {
            let program = prog.lock().expect("program lock poisoned");
            let nmover = nmover.map(str::to_string).unwrap_or_else(|| {
                program.get_domain_file().map(|file| file.get_name()).unwrap_or_default()
            });
            let archover = archover.map(str::to_string).unwrap_or_else(|| program.get_language_id());
            let compover = compover.map(str::to_string).unwrap_or_else(|| {
                program
                    .get_compiler_spec_id()
                    .map(|id| id.get_id_as_string().to_string())
                    .unwrap_or_default()
            });
            let md5string = program.get_executable_md5().filter(|md5| md5.len() >= 10);
            (nmover, archover, compover, md5string)
        };
        let md5string = md5string
            .unwrap_or_else(|| Self::generate_metadata_md5(&nmover, &compover, &archover));

        self.program = Some(prog);
        let prog_date = self.fillin_date();
        let mut manager = DescriptionManager::new();
        let exerec = manager.new_executable_record(
            &md5string, &nmover, &compover, &archover, prog_date, repo, path, None,
        )?;
        self.exerec = Some(exerec);
        self.manager = Some(manager);
        self.fillin_executable_categories();
        Ok(())
    }

    /// Copy the executable categories named by [`add_executable_categories`](Self::add_executable_categories)
    /// out of the program's properties and onto the executable record.
    ///
    /// A category type may appear several times: after `Type` the search continues with
    /// `Type_1`, `Type_2`, ... until a property is missing or is not a string.
    fn fillin_executable_categories(&mut self) {
        let Some(categories) = self.categories.clone() else {
            return;
        };
        let Some(program) = self.program.clone() else {
            return;
        };
        let mut catrecs: Vec<CategoryRecord> = Vec::new();
        {
            let program = program.lock().expect("program lock poisoned");
            let progoptions = program.get_options(PROGRAM_INFO);
            for cat in &categories {
                // Search for each of the categories we want to record.
                let mut curproperty = cat.clone();
                let mut count = 0;
                while progoptions.contains(&curproperty) {
                    let optionobject = progoptions.get_object(&curproperty, Box::new(()));
                    let Some(value) = optionobject.downcast_ref::<String>() else {
                        break;
                    };
                    catrecs.push(CategoryRecord::new(cat.clone(), Some(value.clone())));
                    count += 1;
                    curproperty = format!("{cat}_{count}");
                }
            }
        }
        if let (false, Some(manager), Some(exerec)) =
            (catrecs.is_empty(), self.manager.as_ref(), self.exerec.as_ref())
        {
            manager.set_exe_categories(exerec, Some(catrecs));
        }
    }

    /// The ingest date to stamp on the executable record, in milliseconds since the epoch.
    ///
    /// Without an explicit date column (or with one naming the creation date) this is the
    /// program's creation date; otherwise the named property is read and interpreted as a date.
    fn fillin_date(&self) -> i64 {
        let Some(program) = self.program.as_ref() else {
            return ExecutableRecord::EMPTY_DATE;
        };
        let program = program.lock().expect("program lock poisoned");
        let date_column_name = match self.date_column_name.as_deref() {
            None => return program.get_creation_date(),
            Some(name) if name == DATE_CREATED || name == INGEST_DATE => {
                return program.get_creation_date();
            }
            Some(name) => name,
        };
        let progoptions = program.get_options(PROGRAM_INFO);
        if !progoptions.contains(date_column_name) {
            return ExecutableRecord::EMPTY_DATE;
        }
        let optionobject = progoptions.get_object(date_column_name, Box::new(()));
        // Java's `instanceof Date`; dates are epoch milliseconds throughout the BSim port.
        if let Some(millis) = optionobject.downcast_ref::<i64>() {
            return *millis;
        }
        if let Some(text) = optionobject.downcast_ref::<String>() {
            if text.len() == 19 {
                // Java parses with AbstractSQLFunctionDatabase.JAVA_TIME_FORMAT, which is
                // "yyyy-MM-dd HH:mm:ss.SSSZ". A 19-character string stops right after the
                // seconds, so the pattern's ".SSSZ" tail always runs off the end of the input
                // and `SimpleDateFormat.parse` throws -- leaving Java's result at EMPTY_DATE.
                return ExecutableRecord::EMPTY_DATE;
            }
        }
        ExecutableRecord::EMPTY_DATE
    }

    /// Resolve the target of a call at `addr` into the triple that identifies it in the
    /// database.
    ///
    /// A call that lands on a real function body in this executable is recorded with that
    /// function's entry point; anything else (no function, an external, or an entry point with
    /// no body) is recorded as an external call against a library executable, with address -1.
    fn fillin_properties(&mut self, addr: &Address) -> CallRecord {
        let mut call_record = CallRecord::default();
        let Some(program) = self.program.clone() else {
            return call_record;
        };

        let (func, root_symbol, root_addr) = {
            let mut program = program.lock().expect("program lock poisoned");
            let func = program
                .get_function_manager()
                .and_then(|fmanage| fmanage.get_referenced_function(addr));
            match func {
                // Found no function at all -- look for any primary symbol.
                None => {
                    let symbol = program
                        .get_symbol_table()
                        .and_then(|symtab| symtab.get_primary_symbol(addr).ok().flatten());
                    (None, symbol, None)
                }
                Some(mut func) => {
                    if func.is_thunk() {
                        // Function looks like a thunk.
                        if let Some(thunked) = func.get_thunked_function(true) {
                            func = thunked;
                        }
                    }
                    let root_addr = func.get_entry_point();
                    let root_symbol = Namespace::get_symbol(&*func);
                    (Some(func), Some(root_symbol), Some(root_addr))
                }
            }
        };

        let hasbody = match (&func, &root_addr) {
            (Some(func), Some(root_addr)) if !Function::is_external(&**func) => {
                self.has_body(root_addr)
            }
            _ => false,
        };

        if hasbody {
            // Internal call, within the same executable.
            call_record.exerec = self.exerec.clone();
            call_record.address = root_addr.expect("root address set with the function").offset();
            call_record.funcname = root_symbol
                .as_ref()
                .map(|symbol| qualified_symbol_name(&**symbol))
                .unwrap_or_default();
            return call_record;
        }

        // Treat as external call; the address is not available, so -1 marks it as external.
        call_record.address = -1;
        let library_name = match root_symbol.as_ref() {
            None => {
                // Make up a name.
                call_record.funcname = format!("func_{:x}", addr.offset() as u64);
                UNKNOWN_LIBRARY.to_string()
            }
            Some(symbol) => Self::extract_external_name(&**symbol, &mut call_record),
        };
        let architecture =
            self.exerec.as_ref().map(|exerec| exerec.get_architecture().to_string());
        call_record.exerec = match (self.manager.as_mut(), architecture) {
            (Some(manager), Some(architecture)) => {
                manager.new_executable_library(&library_name, &architecture, None).ok()
            }
            _ => None,
        }
        // If we couldn't create a library executable, use the original executable.
        .or_else(|| self.exerec.clone());
        call_record
    }

    /// Split a namespace-qualified external symbol name into the library it belongs to and the
    /// bare function name, which is written into `call_record`.
    ///
    /// The first namespace is the library; a name with no namespace, an empty library or an
    /// empty function part all fall back to the `"unknown"` library.
    fn extract_external_name(sym: &dyn Symbol, call_record: &mut CallRecord) -> String {
        let full_name = qualified_symbol_name(sym);
        let Some(ind) = full_name.find(DELIMITER) else {
            call_record.funcname = full_name;
            return UNKNOWN_LIBRARY.to_string();
        };
        // First namespace is name of library.
        let mut library_name = full_name[..ind].to_string();
        // Cut off first namespace.
        let tmpnm = &full_name[ind + DELIMITER.len()..];
        if tmpnm.is_empty() {
            call_record.funcname = full_name;
            return UNKNOWN_LIBRARY.to_string();
        }
        call_record.funcname = tmpnm.to_string();
        if library_name.is_empty() || library_name == library::UNKNOWN {
            library_name = UNKNOWN_LIBRARY.to_string();
        }
        library_name
    }

    /// Collect the BSim flag bits for `func` from the bookmarks at its entry point and from its
    /// function tags, using the mapping built by
    /// [`add_function_tags`](Self::add_function_tags).
    fn recover_attributes(&self, func: &dyn Function) -> i32 {
        let mut flags = 0;
        if let Some(program) = self.program.as_ref() {
            let bookmark_manager = {
                let program = program.lock().expect("program lock poisoned");
                program.get_bookmark_manager()
            };
            if let Some(bookmark_manager) = bookmark_manager {
                for bookmark in bookmark_manager.get_bookmarks_at(func.get_entry_point()) {
                    if let Some(val) = self.attributes.get(bookmark.get_category()) {
                        flags |= val;
                    }
                }
            }
        }
        for tag in func.get_tags() {
            if let Some(val) = self.attributes.get(tag.name()) {
                flags |= val;
            }
        }
        flags
    }

    /// Resolve every call address the decompiler reported into a [`CallRecord`].
    fn collect_calls_from_address(&mut self, calladdr: &[Address]) -> Vec<CallRecord> {
        calladdr.iter().map(|addr| self.fillin_properties(addr)).collect()
    }

    /// Return true if the address corresponds to a normal function body.
    ///
    /// `addr` is the entry point of the function. An entry point that is data, or whose first
    /// instruction is a computed jump (a dispatch stub), has no body.
    fn has_body(&self, addr: &Address) -> bool {
        let Some(program) = self.program.as_ref() else {
            return false;
        };
        let mut program = program.lock().expect("program lock poisoned");
        let Some(listing) = program.get_listing() else {
            return false;
        };
        let Some(code_unit) = listing.get_code_unit_at(addr) else {
            return false;
        };
        // If the entry point is data -> no body.
        let Some(instruction) = code_unit.as_instruction() else {
            return false;
        };
        instruction.get_flow_type() != RefType::ComputedJump
    }

    /// Record `func` in the container: its metadata, its signature (when `hash` carries the
    /// decompiler's feature hashes) and one callgraph edge per entry of `callrecs`.
    ///
    /// Java marks this `synchronized` because the parallel decompiler calls it from several
    /// worker threads; `&mut self` gives the same exclusion here.
    fn write_to_manager(
        &mut self,
        func: &dyn Function,
        hash: Option<&[i32]>,
        callrecs: &[CallRecord],
        flags: i32,
    ) {
        let (Some(exerec), Some(_)) = (self.exerec.clone(), self.manager.as_ref()) else {
            return;
        };
        let name = Namespace::get_name_with_path(func, true);
        let address = func.get_entry_point().offset();
        let signature = hash.zip(self.vector_factory.clone()).map(|(hash, vector_factory)| {
            let vec = vector_factory.build_vector(hash);
            self.manager.as_ref().expect("manager checked above").new_signature(&vec, 0)
        });

        let manager = self.manager.as_mut().expect("manager checked above");
        let mut fdesc = manager.new_function_description(&name, address, exerec);
        manager.set_function_description_flags(&mut fdesc, flags);
        if let Some(sigrec) = signature {
            manager.attach_signature(&mut fdesc, Arc::new(sigrec));
        }
        for call_record in callrecs {
            let Some(dest_exerec) = call_record.exerec.clone() else {
                continue;
            };
            let destfunc = manager.new_function_description(
                &call_record.funcname,
                call_record.address,
                dest_exerec,
            );
            manager.make_callgraph_link(&mut fdesc, Arc::new(destfunc), 0);
        }
        manager.insert_function(fdesc);
    }

    /// Copy the already-generated descriptions of `functions` into `otherman`, keeping only
    /// those the pre-filter accepts. Returns how many were transferred.
    ///
    /// Functions this generator has no description for are skipped.
    ///
    /// # Errors
    /// If no program is open, or if a function's executable clashes with one already in
    /// `otherman`.
    pub fn transfer_cached_functions<I>(
        &self,
        otherman: &mut DescriptionManager,
        functions: I,
        pre_filter: &PreFilter,
    ) -> Result<i32, LshException>
    where
        I: IntoIterator<Item = Arc<dyn Function>>,
    {
        let (Some(manager), Some(exerec), Some(program)) =
            (self.manager.as_ref(), self.exerec.as_ref(), self.program.as_ref())
        else {
            return Err(LshException::new("No program is open"));
        };
        otherman.transfer_settings(manager);
        let mut count = 0;
        let filter_predicate = pre_filter.get_and_reduced_predicate();
        let program = program.lock().expect("program lock poisoned");
        for func in functions {
            let name = Namespace::get_name_with_path(&*func, true);
            let address = func.get_entry_point().offset();
            // find_function errors if the manager holds no function of this name; skip it.
            let Ok(desc) = manager.find_function(&name, address, exerec) else {
                continue;
            };
            if filter_predicate(&*program, desc) {
                otherman.transfer_function(desc, true)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Generate just the update metadata (name, address, flags) for functions in the currently
    /// open program. Passing `None` for `iter` covers every function in the program.
    pub fn scan_functions_metadata<I>(&mut self, iter: Option<I>, monitor: Option<&dyn TaskMonitor>)
    where
        I: IntoIterator<Item = Arc<dyn Function>>,
    {
        if self.exerec.is_none() {
            return; // No current executable
        }
        let functions: Vec<Arc<dyn Function>> = match iter {
            Some(iter) => iter.into_iter().collect(),
            None => {
                let Some(program) = self.program.clone() else {
                    return;
                };
                let mut program = program.lock().expect("program lock poisoned");
                match program.get_function_manager() {
                    Some(fmanage) => fmanage.get_functions(true).collect(),
                    None => Vec::new(),
                }
            }
        };
        for func in functions {
            if monitor.is_some_and(|monitor| monitor.is_cancelled()) {
                return;
            }
            if func.is_thunk() {
                continue;
            }
            let entry_point = func.get_entry_point();
            if !self.has_body(&entry_point) {
                continue;
            }
            let flags = self.recover_attributes(&*func);
            let name = Namespace::get_name_with_path(&*func, true);
            let exerec = self.exerec.clone().expect("executable record checked above");
            let manager = self.manager.as_mut().expect("manager set with the executable record");
            let mut fdesc = manager.new_function_description(&name, entry_point.offset(), exerec);
            manager.set_function_description_flags(&mut fdesc, flags);
            manager.insert_function(fdesc);
        }
    }

    /// Shut the generator down: no further scanning is accepted and the accumulated signatures
    /// are dropped.
    pub fn dispose(&mut self) {
        self.is_shutdown.store(true, Ordering::SeqCst);
        self.clear();
    }

    /// True once [`dispose`](Self::dispose) has been called.
    pub fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::SeqCst)
    }

    /// Build an [`ExecutableRecord`] path from the program's domain file.
    ///
    /// Returns the path to this program within the repository, or `None` when the domain file's
    /// pathname does not end in its own name (which is what an unsaved program looks like).
    ///
    /// **WARNING:** make sure the program has been saved previously before calling this,
    /// otherwise you get an (inaccurate) result of `"/"`.
    pub fn get_path_from_domain_file(program: &dyn Program) -> Option<String> {
        let domain_file = program.get_domain_file()?;
        let path = domain_file.get_pathname();
        let name = domain_file.get_name();
        let ind = path.len().checked_sub(name.len())?;
        if path[ind..] != name {
            return None;
        }
        if ind == 0 {
            return None;
        }
        Some(path[..ind].to_string())
    }

    /// Return the weights file that should be used to compare functions between two programs.
    ///
    /// `id1` is the language of the first program and `id2` that of the second (which may be
    /// the same). Returns `None` if there is no valid weights file for the pair. `app` supplies
    /// the module data directory Java reaches through the static `Application`.
    ///
    /// # Errors
    /// If the module data directory cannot be found.
    pub fn get_weights_file(
        app: &dyn Application,
        id1: &LanguageID,
        id2: &LanguageID,
    ) -> io::Result<Option<ResourceFile>> {
        let split1: Vec<&str> = id1.get_id_as_string().split(':').collect();
        let split2: Vec<&str> = id2.get_id_as_string().split(':').collect();
        // Check if we are comparing the same processor size; if not, we need to do something
        // different with the weights.
        if split1.len() < 3 || split2.len() < 3 {
            return Ok(None);
        }

        let module_data_sub_directory = app.get_module_data_sub_directory(BSIM_MODULE, "")?;
        if split1[0] == "Dalvik" || split1[0] == "JVM" {
            if split2[0] != split1[0] {
                return Ok(None);
            }
            return Ok(Some(module_data_sub_directory.join("lshweights_cpool.xml")));
        }

        // Pull out the size.
        let size1 = split1[2];
        let size2 = split2[2];
        let basefile = if size1 != size2 {
            // The two things we compare are from different processor sizes; unless both are 32
            // or 64 we cannot do decent comparisons.
            if (size1 != "64" && size1 != "32") || (size2 != "64" && size2 != "32") {
                return Ok(None);
            }
            // We use a special sizeless weights file.
            "lshweights_nosize.xml"
        } else if size1 == "32" {
            "lshweights_32.xml"
        } else if size1 == "64" {
            match split1.get(3) {
                Some(version) if version.contains("-32") => "lshweights_64_32.xml",
                _ => "lshweights_64.xml",
            }
        } else {
            // Same size, but not 64 or 32.
            "lshweights_nosize.xml"
        };

        Ok(Some(module_data_sub_directory.join(basefile)))
    }
}

/// The Ghidra module the BSim weights files live in.
const BSIM_MODULE: &str = "BSim";

/// The namespace-qualified name of a symbol, i.e. Java's `Symbol.getName(true)`.
fn qualified_symbol_name(sym: &dyn Symbol) -> String {
    let mut parts =
        sym.get_parent_namespace().map(|ns| ns.get_path_list(false)).unwrap_or_default();
    parts.push(sym.get_name().to_string());
    parts.join(DELIMITER)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- construction ---

    #[test]
    fn test_new_seeds_the_function_id_analyzer_attribute() {
        let gen = GenSignatures::new(true);
        assert!(gen.generates_callgraph());
        assert_eq!(
            gen.attributes.get("Function ID Analyzer"),
            Some(&FunctionTagBSimFilterType::KNOWN_LIBRARY_MASK)
        );
        assert!(gen.categories.is_none());
        assert!(gen.date_column_name.is_none());
        assert!(gen.get_description_manager().is_none());
    }

    // --- add_executable_categories ---

    #[test]
    fn test_add_executable_categories_accumulates() {
        let mut gen = GenSignatures::new(false);
        gen.add_executable_categories(&["Origin"]).unwrap();
        gen.add_executable_categories(&["Vendor", "Release"]).unwrap();
        assert_eq!(gen.categories.as_deref(), Some(&["Origin", "Vendor", "Release"].map(String::from)[..]));
    }

    #[test]
    fn test_add_executable_categories_rejects_illegal_characters() {
        let mut gen = GenSignatures::new(false);
        assert!(gen.add_executable_categories(&["bad,name"]).is_err());
    }

    // --- add_function_tags ---

    #[test]
    fn test_add_function_tags_assigns_bits_above_the_reserved_ones() {
        let mut gen = GenSignatures::new(false);
        gen.add_function_tags(&["alpha", "beta", "gamma"]).unwrap();
        // RESERVED_BITS is 3, so the first user tag is 1 << 3 == 8 and each doubles.
        assert_eq!(gen.attributes.get("alpha"), Some(&8));
        assert_eq!(gen.attributes.get("beta"), Some(&16));
        assert_eq!(gen.attributes.get("gamma"), Some(&32));
        // The built-in mapping survives.
        assert_eq!(gen.attributes.get("Function ID Analyzer"), Some(&1));
    }

    #[test]
    fn test_add_function_tags_bits_never_collide_with_the_builtin_masks() {
        let mut gen = GenSignatures::new(false);
        gen.add_function_tags(&["alpha"]).unwrap();
        let builtin = FunctionTagBSimFilterType::KNOWN_LIBRARY_MASK
            | FunctionTagBSimFilterType::HAS_UNIMPLEMENTED_MASK
            | FunctionTagBSimFilterType::HAS_BADDATA_MASK;
        assert_eq!(gen.attributes["alpha"] & builtin, 0);
    }

    #[test]
    fn test_add_function_tags_rejects_more_than_max_tag_count() {
        let mut gen = GenSignatures::new(false);
        let names: Vec<String> = (0..=FunctionTagBSimFilterType::MAX_TAG_COUNT)
            .map(|i| format!("tag{i}"))
            .collect();
        assert!(gen.add_function_tags(&names).is_err());
    }

    #[test]
    fn test_add_function_tags_accepts_exactly_max_tag_count() {
        let mut gen = GenSignatures::new(false);
        let names: Vec<String> =
            (0..FunctionTagBSimFilterType::MAX_TAG_COUNT).map(|i| format!("tag{i}")).collect();
        gen.add_function_tags(&names).unwrap();
        // The last tag lands on the sign bit.
        assert_eq!(gen.attributes["tag28"], i32::MIN);
    }

    #[test]
    fn test_add_function_tags_rejects_illegal_characters() {
        let mut gen = GenSignatures::new(false);
        assert!(gen.add_function_tags(&["bad,tag"]).is_err());
    }

    // --- set_vector_factory ---

    #[test]
    fn test_set_vector_factory_rejects_zero_settings() {
        let mut gen = GenSignatures::new(false);
        let err = gen.set_vector_factory(Arc::new(LSHVectorFactory::default())).unwrap_err();
        assert_eq!(err.message(), "Cannot have signature setting of 0");
        assert!(gen.get_vector_factory().is_none());
    }

    #[test]
    fn test_set_vector_factory_accepts_nonzero_settings() {
        let mut gen = GenSignatures::new(false);
        let factory = Arc::new(LSHVectorFactory::with_settings(7));
        gen.set_vector_factory(Arc::clone(&factory)).unwrap();
        assert!(Arc::ptr_eq(gen.get_vector_factory().unwrap(), &factory));
    }

    // --- add_date_column_name ---

    #[test]
    fn test_add_date_column_name_rejects_illegal_characters() {
        let mut gen = GenSignatures::new(false);
        assert!(gen.add_date_column_name("bad,column").is_err());
        assert!(gen.date_column_name.is_none());
    }

    #[test]
    fn test_add_date_column_name_accepts_legal_name() {
        let mut gen = GenSignatures::new(false);
        gen.add_date_column_name("Ingest Date").unwrap();
        assert_eq!(gen.date_column_name.as_deref(), Some("Ingest Date"));
    }

    // --- generate_metadata_md5 ---

    #[test]
    fn test_generate_metadata_md5_matches_java() {
        // Java concatenates the three strings byte-wise and MD5s the result, so the hash equals
        // the MD5 of "notepad.exewindowsx86:LE:32:default".
        assert_eq!(
            GenSignatures::generate_metadata_md5("notepad.exe", "windows", "x86:LE:32:default"),
            "e5a7eb614bebf020f53a78e1dc5b5f84"
        );
    }

    #[test]
    fn test_generate_metadata_md5_of_empty_metadata_is_the_md5_of_the_empty_string() {
        assert_eq!(
            GenSignatures::generate_metadata_md5("", "", ""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn test_generate_metadata_md5_depends_on_field_order() {
        // The fields are concatenated, so a shift between them changes the hash.
        let a = GenSignatures::generate_metadata_md5("ab", "c", "d");
        let b = GenSignatures::generate_metadata_md5("a", "bc", "d");
        assert_eq!(a, b, "concatenation makes these two indistinguishable, as in Java");
        let c = GenSignatures::generate_metadata_md5("a", "b", "c");
        assert_ne!(a, c);
    }

    // --- dispose / clear ---

    #[test]
    fn test_dispose_marks_shutdown_and_clears() {
        let mut gen = GenSignatures::new(false);
        assert!(!gen.is_shutdown());
        gen.dispose();
        assert!(gen.is_shutdown());
        assert!(gen.get_description_manager().is_none());
    }

    // --- get_weights_file ---

    struct StubApplication {
        data_dir: std::path::PathBuf,
    }

    impl Application for StubApplication {
        fn application_layout(
            &self,
        ) -> Box<dyn crate::framework::seam_stubs::ApplicationLayoutLike> {
            unimplemented!("get_weights_file only reaches the module data directory")
        }

        fn current_platform(&self) -> Box<dyn crate::framework::Platform> {
            unimplemented!("get_weights_file only reaches the module data directory")
        }

        fn get_module_data_sub_directory(
            &self,
            _module_name: &str,
            relative_path: &str,
        ) -> io::Result<ResourceFile> {
            Ok(ResourceFile::new(self.data_dir.join(relative_path)))
        }
    }

    fn weights_file_name(id1: &str, id2: &str) -> Option<String> {
        let app = StubApplication { data_dir: std::path::PathBuf::from("/ghidra/BSim/data") };
        GenSignatures::get_weights_file(
            &app,
            &LanguageID::new(id1).unwrap(),
            &LanguageID::new(id2).unwrap(),
        )
        .unwrap()
        .map(|file| file.name())
    }

    #[test]
    fn test_get_weights_file_same_32_bit_language() {
        assert_eq!(
            weights_file_name("x86:LE:32:default", "x86:LE:32:default").as_deref(),
            Some("lshweights_32.xml")
        );
    }

    #[test]
    fn test_get_weights_file_same_64_bit_language() {
        assert_eq!(
            weights_file_name("x86:LE:64:default", "x86:LE:64:default").as_deref(),
            Some("lshweights_64.xml")
        );
    }

    #[test]
    fn test_get_weights_file_64_bit_variant_with_32_bit_pointers() {
        assert_eq!(
            weights_file_name("x86:LE:64:compat-32", "x86:LE:64:default").as_deref(),
            Some("lshweights_64_32.xml")
        );
    }

    #[test]
    fn test_get_weights_file_mixed_32_and_64_bit() {
        assert_eq!(
            weights_file_name("x86:LE:32:default", "x86:LE:64:default").as_deref(),
            Some("lshweights_nosize.xml")
        );
    }

    #[test]
    fn test_get_weights_file_same_but_unusual_size() {
        assert_eq!(
            weights_file_name("MCS96:LE:16:default", "MCS96:LE:16:default").as_deref(),
            Some("lshweights_nosize.xml")
        );
    }

    #[test]
    fn test_get_weights_file_mixed_sizes_neither_32_nor_64() {
        assert_eq!(weights_file_name("MCS96:LE:16:default", "x86:LE:32:default"), None);
    }

    #[test]
    fn test_get_weights_file_cpool_languages() {
        assert_eq!(
            weights_file_name("JVM:BE:32:default", "JVM:BE:32:default").as_deref(),
            Some("lshweights_cpool.xml")
        );
        assert_eq!(
            weights_file_name("Dalvik:LE:32:default", "Dalvik:LE:32:default").as_deref(),
            Some("lshweights_cpool.xml")
        );
    }

    #[test]
    fn test_get_weights_file_cpool_language_against_a_native_one() {
        assert_eq!(weights_file_name("JVM:BE:32:default", "x86:LE:32:default"), None);
    }

    #[test]
    fn test_get_weights_file_underspecified_language_id() {
        assert_eq!(weights_file_name("x86:LE", "x86:LE:32:default"), None);
    }
}
