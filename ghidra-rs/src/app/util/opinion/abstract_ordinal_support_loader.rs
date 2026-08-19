//! Port of `ghidra.app.util.opinion.AbstractOrdinalSupportLoader`.
//!
//! Support for programs that link to external libraries with an ordinal mechanism, caching the
//! library lookup information to XML files (see
//! [`library_lookup_table`](crate::app::util::opinion::library_lookup_table)).
//!
//! The Java class is abstract, holds no instance state, and exists purely so its subclasses
//! (`PeLoader`, `Omf51Loader`, ...) inherit these overrides, so it is ported as a trait of default
//! methods rather than a struct.
//!
//! # Departures from the Java class
//!
//! * `AbstractOrdinalSupportLoader extends AbstractLibrarySupportLoader` (in turn
//!   `AbstractProgramLoader`, in turn `Loader`), none of which are ported. This trait therefore
//!   has no supertrait -- requiring [`Loader`](crate::app::util::opinion::loader::Loader) would
//!   force every implementor to supply the whole inherited loading machinery this class never
//!   defines -- and the `super.xxx(..)` calls are handled the same way
//!   [`ElfLoader`](crate::app::util::opinion::elf_loader::ElfLoader) handles them:
//!   `super.getDefaultOptions(..)`'s result becomes an explicit `base_options` parameter, while
//!   `super.validateOptions(..)`, `super.postLoadProgramFixups(..)` and
//!   `super.postLoadCleanup(..)` contribute nothing here (their bodies live in the unported
//!   parent). `createArg("-ordinalLookup")` likewise resolves to `Loader`'s default, so
//!   [`COMMAND_LINE_ARG_PREFIX`] is applied directly.
//! * The `ImporterSettings` parameter that Java threads through the four overridden methods is
//!   unpacked into the individual pieces each one actually reads -- the same substitution
//!   `ElfLoader::post_load_program_fixups` makes -- because the ported
//!   [`ImporterSettings`](crate::app::util::opinion::loader::ImporterSettings) carries its option
//!   list and load spec as the marker placeholders `OptionLike`/`LoadSpecLike`, which expose no
//!   members. So `settings.options()` becomes an `options: &[Box<dyn Option>]` parameter,
//!   `settings.log()`/`settings.monitor()` become `log`/`monitor`, and the architecture size that
//!   Java reads out of `settings.loadSpec().getLanguageCompilerSpec().getLanguageDescription()`
//!   becomes a `size` parameter to [`AbstractOrdinalSupportLoader::process_library`].
//! * `postLoadProgramFixups` takes `&mut [&mut dyn Program]` rather than `List<Loaded<Program>>`:
//!   the ported [`Loaded`](crate::app::util::opinion::loaded::Loaded) is not generic over its
//!   domain object type and only ever hands out `&dyn DomainObject`, which cannot be narrowed
//!   back to a `Program`. Consequently the `getDomainObject(this)`/`release(this)` consumer
//!   bookkeeping around each program is the caller's business here; everything between those two
//!   calls (the `isTemporary` filter, the monitor, the transaction, and the two fixups) is
//!   reproduced.
//! * `FileSystemService.getInstance()` and `Application`'s equivalent singleton were both dropped
//!   when those classes were ported, so [`process_library`](AbstractOrdinalSupportLoader::process_library)
//!   takes explicit `local_fs`/`app` parameters (and every other method that reaches
//!   `LibraryLookupTable` takes `app`).
//! * `validateOptions`'s message drops the `" - " + option.getValueClass()` suffix: the ported
//!   [`Option`] placeholder has no working `getValueClass`, so the type check is made by
//!   downcasting `get_value()` instead and there is no class name to name.
//! * `Option.newBoolean(..)` is built through the [`Option`] placeholder's builder, whose
//!   `stateKey` setter was grown for this class.
//! * Symbols in the global namespace report `None` from
//!   [`Symbol::get_parent_namespace`](crate::program::model::symbol::Symbol::get_parent_namespace)
//!   rather than the global namespace itself, so `applyLibrarySymbols`' namespace equality check
//!   accepts both that and an explicit id match.
//! * `applyImports` reaches its external locations twice: once immutably (through the
//!   `Arc`-yielding iterator) to read each label, then again through
//!   [`ExternalManager::get_external_location_mut`](crate::program::model::symbol::ExternalManager::get_external_location_mut)
//!   to apply a fix, since Java's freely mutable `ExternalLocation` reference has no direct
//!   equivalent. A location with no symbol, or an `ExternalLocation` implementation that does not
//!   support mutable access (or [`ExternalLocation::create_function_mut`]), is left unmodified.

use std::sync::Arc;

use crate::app::seam_stubs::{new_boolean, option_utils, LibrarySymbolTable, MessageLog, Option};
use crate::app::util::opinion::library_lookup_table::{self, file_name_of, CreateFileError};
use crate::app::util::opinion::loader::{COMMAND_LINE_ARG_PREFIX, OPTIONS_PROJECT_SAVE_STATE_KEY};
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::seam_stubs::LocalFileSystemLike;
use crate::framework::application::Application;
use crate::framework::options::Options;
use crate::program::model::listing::{Program, PROGRAM_INFO};
use crate::program::model::symbol::{
    DefaultSymbolUtilities, ExternalLocation, SourceType, SymbolUtilities, ORDINAL_PREFIX,
};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `AbstractOrdinalSupportLoader.ORDINAL_LOOKUP_OPTION_NAME`.
pub const ORDINAL_LOOKUP_OPTION_NAME: &str = "Perform Library Ordinal Lookup";

/// `AbstractOrdinalSupportLoader.ORDINAL_LOOKUP_OPTION_DEFAULT`, package-private in Java.
pub(crate) const ORDINAL_LOOKUP_OPTION_DEFAULT: bool = true;

/// A loader for programs that link to external libraries with an ordinal mechanism.
///
/// Port of the abstract class `ghidra.app.util.opinion.AbstractOrdinalSupportLoader`; see the
/// module docs for why it is a trait and how its `ImporterSettings` parameters were unpacked.
pub trait AbstractOrdinalSupportLoader {
    /// `getDefaultOptions(ByteProvider, LoadSpec, DomainObject, boolean, boolean)`: appends the
    /// ordinal-lookup option to the ones inherited from the (unported) superclass.
    fn get_default_options(&self, base_options: Vec<Box<dyn Option>>) -> Vec<Box<dyn Option>> {
        let mut list = base_options;
        list.push(
            new_boolean(ORDINAL_LOOKUP_OPTION_NAME)
                .value(Box::new(ORDINAL_LOOKUP_OPTION_DEFAULT))
                .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-ordinalLookup"))
                .state_key(OPTIONS_PROJECT_SAVE_STATE_KEY.to_string())
                .build(),
        );
        list
    }

    /// `validateOptions(ByteProvider, LoadSpec, List<Option>, Program)`: `None` if the
    /// ordinal-lookup option (if present at all) holds a boolean; otherwise a message naming it.
    ///
    /// `options` is optional to mirror the `options != null` guard Java opens with.
    fn validate_options(&self, options: std::option::Option<&[Box<dyn Option>]>) -> std::option::Option<String> {
        for option in options.unwrap_or(&[]) {
            let name = option.get_name();
            if name == ORDINAL_LOOKUP_OPTION_NAME && !option.get_value().is::<bool>() {
                return Some(format!("Invalid type for option: {name}"));
            }
        }
        None
    }

    /// `shouldSearchAllPaths(Program, ImporterSettings)`. Java's unused `Program` parameter is
    /// dropped.
    fn should_search_all_paths(&self, options: &[Box<dyn Option>]) -> bool {
        should_perform_ordinal_lookup(options)
    }

    /// `processLibrary(Program, String, FSRL, Queue<UnprocessedLibrary>, int, ImporterSettings)`:
    /// makes sure `lib_name` has an up-to-date `.exports` file. Java's `unprocessed` queue and
    /// `depth` parameters are unused by this override and so are dropped.
    ///
    /// `size` is the architecture size of the load spec in use; see the module docs.
    ///
    /// # Errors
    /// Returns `Err` if the user cancelled while a new exports file was being written. An IO
    /// failure there is reported to `log` instead, as in Java.
    #[allow(clippy::too_many_arguments)]
    fn process_library(
        &self,
        lib: &dyn Program,
        lib_name: &str,
        lib_fsrl: &dyn Fsrl,
        size: i32,
        app: &dyn Application,
        local_fs: &dyn LocalFileSystemLike,
        options: &[Box<dyn Option>],
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let existing_exports_file = library_lookup_table::get_existing_exports_file(app, lib_name, size);

        if !should_perform_ordinal_lookup(options) {
            return Ok(());
        }

        match existing_exports_file {
            // Create exports file if necessary
            None => match library_lookup_table::create_file(app, lib, true, monitor) {
                Ok(new_exports_file) => {
                    log.append_msg(&format!(
                        "Created exports file: {}",
                        new_exports_file.absolute_path()
                    ));
                }
                Err(CreateFileError::Io(_)) => {
                    log.append_msg(&format!(
                        "Unable to create exports file for {}",
                        lib_fsrl.fsrl_string()
                    ));
                }
                Err(CreateFileError::Cancelled(e)) => return Err(e),
            },
            Some(existing_exports_file) => {
                log.append_msg(&format!(
                    "Using existing exports file: {}",
                    existing_exports_file.absolute_path()
                ));
                if let Some(local_lib_file) = get_local_file(local_fs, lib_fsrl) {
                    if !library_lookup_table::has_file_and_path_and_time_stamp_match(
                        app,
                        &local_lib_file,
                        size,
                    ) {
                        log.append_msg("WARNING: Existing exports file may not be an exact match.");
                    }
                }
            }
        }

        Ok(())
    }

    /// `postLoadProgramFixups(List<Loaded<Program>>, ImporterSettings)`: applies the library
    /// symbol tables to every non-temporary program that was loaded. See the module docs for why
    /// the programs are passed directly rather than as `Loaded`s.
    ///
    /// # Errors
    /// Returns `Err` if the user cancelled the load.
    fn post_load_program_fixups(
        &self,
        loaded_programs: &mut [&mut dyn Program],
        app: &dyn Application,
        options: &[Box<dyn Option>],
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        if !should_perform_ordinal_lookup(options) {
            return Ok(());
        }

        let saveable_count = loaded_programs.iter().filter(|p| !p.is_temporary()).count();
        monitor.initialize(saveable_count as i64);

        for program in loaded_programs.iter_mut().filter(|p| !p.is_temporary()) {
            monitor.check_cancelled()?;
            let program: &mut dyn Program = &mut **program;
            let id = program.start_transaction("Ordinal fixups");
            let result = apply_library_symbols(program, app, log, monitor)
                .and_then(|()| apply_imports(program, app, log, monitor));
            // More efficient to commit when program will be discarded
            program.end_transaction(id, true);
            result?;
        }

        Ok(())
    }

    /// `postLoadCleanup(boolean)`: discards the exports files that were written but not worth
    /// keeping.
    fn post_load_cleanup(&self, success: bool) {
        let _ = success;
        library_lookup_table::cleanup();
    }
}

/// `shouldPerformOrdinalLookup(ImporterSettings)`: whether ordinal lookup should be performed.
fn should_perform_ordinal_lookup(options: &[Box<dyn Option>]) -> bool {
    option_utils::get_bool_option(ORDINAL_LOOKUP_OPTION_NAME, options, ORDINAL_LOOKUP_OPTION_DEFAULT)
}

/// `getLocalFile(FSRL)`: if `fsrl` is from a local filesystem, its corresponding local file.
fn get_local_file(
    local_fs: &dyn LocalFileSystemLike,
    fsrl: &dyn Fsrl,
) -> std::option::Option<std::path::PathBuf> {
    local_fs.get_local_file(fsrl).ok()
}

/// `applyLibrarySymbols(Program, MessageLog, TaskMonitor)`: applies the library symbol table to
/// the program being loaded. For example, loading "mfc42.dll" creates the named symbols alongside
/// the ordinals.
///
/// # Panics
/// Panics if `program` has no language, mirroring Java's uncaught `NullPointerException` out of
/// `program.getLanguage().getLanguageDescription()`.
fn apply_library_symbols(
    program: &mut dyn Program,
    app: &dyn Application,
    log: &dyn MessageLog,
    monitor: &dyn TaskMonitor,
) -> Result<(), CancelledException> {
    monitor.set_message(&format!("Applying information...{}", Program::get_name(program)));

    // Check based on the original program name, not on the name I gave this program
    let size = program
        .get_language()
        .expect("program must have a language to apply library symbols")
        .get_language_description()
        .get_size();

    let executable_name = file_name_of(&program.get_executable_path());
    let symtab = library_lookup_table::get_symbol_table_with_log(app, &executable_name, size, Some(log))
        // now try based on the name given to the program
        .or_else(|| {
            library_lookup_table::get_symbol_table_with_log(
                app,
                &Program::get_name(program),
                size,
                Some(log),
            )
        });
    let Some(symtab) = symtab else {
        return Ok(());
    };

    if !is_version_match(program, &symtab, log) {
        return Ok(());
    }

    let global_namespace = program.get_global_namespace();
    let global_namespace_id = global_namespace.as_ref().map(|ns| ns.get_id());

    let Some(symbol_table) = program.get_symbol_table() else {
        return Ok(());
    };

    // Java walks the iterator lazily; the matching symbols are collected up front here because
    // creating a label needs `&mut` on the same symbol table the iterator is borrowed from.
    let mut ordinal_symbols = Vec::new();
    let mut iter = symbol_table.get_symbol_iterator(&format!("{ORDINAL_PREFIX}*"), true);
    while iter.has_next() {
        monitor.check_cancelled()?;
        let Some(ord_sym) = iter.next_symbol() else {
            break;
        };
        if !ord_sym.get_address().is_memory_address() {
            continue;
        }
        let is_global = match ord_sym.get_parent_namespace() {
            // The ported `Symbol` reports a symbol directly in the global namespace as `None`.
            None => true,
            Some(parent) => Some(parent.get_id()) == global_namespace_id,
        };
        if !is_global {
            continue;
        }
        ordinal_symbols.push(ord_sym);
    }
    drop(iter);

    for ord_sym in ordinal_symbols {
        let ordinal = DefaultSymbolUtilities.get_ordinal_value(Some(ord_sym.get_name()));
        let Some(les) = symtab.get_symbol_by_ordinal(ordinal) else {
            continue;
        };
        let Some(name) = les.name() else {
            continue;
        };
        let address = ord_sym.get_address();

        match symbol_table.get_global_symbol(name, &address) {
            Ok(Some(_)) => {}
            Ok(None) => {
                let created = match global_namespace.clone() {
                    Some(namespace) => symbol_table.create_label_in_namespace(
                        &address,
                        name,
                        namespace,
                        SourceType::Imported,
                    ),
                    None => symbol_table.create_label(&address, name, SourceType::Imported),
                };
                match created.and_then(|s| symbol_table.set_primary_symbol(s.get_id())) {
                    Ok(_) => {}
                    Err(e) => log.append_msg(&format!(
                        "Error creating label named {name} at address {address}: {e}"
                    )),
                }
            }
            Err(e) => log.append_msg(&format!(
                "Error creating label named {name} at address {address}: {e}"
            )),
        }
    }

    Ok(())
}

/// `applyImports(Program, MessageLog, TaskMonitor)`: applies the library symbol table to the
/// imported symbols of `program`.
///
/// Java declares no checked exception here (a cancelled monitor just cuts the work short and
/// returns), which the `Ok(())`-only [`Result`] preserves so this composes with
/// [`apply_library_symbols`].
///
/// # Panics
/// Panics if `program` has no language, as [`apply_library_symbols`] does.
fn apply_imports(
    program: &mut dyn Program,
    app: &dyn Application,
    log: &dyn MessageLog,
    monitor: &dyn TaskMonitor,
) -> Result<(), CancelledException> {
    monitor.set_message(&format!("Applying imports...{}", Program::get_name(program)));

    let size = program
        .get_language()
        .expect("program must have a language to apply imports")
        .get_language_description()
        .get_size();

    let Some(em) = program.get_external_manager() else {
        return Ok(());
    };

    for lib in em.get_external_library_names() {
        if monitor.is_cancelled() {
            return Ok(());
        }

        let symtab = library_lookup_table::get_symbol_table_with_log(app, &lib, size, Some(log));

        // Collected up front: applying a fix below needs `&mut` on the same manager the iterator
        // borrows.
        let mut locations = Vec::new();
        let mut iter = em.get_external_locations_for_library(&lib);
        while let Some(location) = iter.next_external_location() {
            locations.push(location);
        }
        drop(iter);

        for ext_loc in locations {
            if monitor.is_cancelled() {
                return Ok(());
            }

            let sym_name = ext_loc.get_label();

            // this check belongs here, because we want to demangle even if we do not have a
            // symbol table...
            let Some(symtab) = symtab.as_deref() else {
                continue;
            };

            // if symbol is imported by ordinal, then see if the library contains a name for that
            // ordinal. if so, then rename the symbol
            let exp_sym = match symtab.get_symbol(&sym_name) {
                Some(exp_sym) => exp_sym,
                None => {
                    let ord = DefaultSymbolUtilities.get_ordinal_value(Some(&sym_name));
                    if ord == -1 {
                        continue;
                    }
                    let Some(exp_sym) = symtab.get_symbol_by_ordinal(ord) else {
                        let exports_file =
                            library_lookup_table::get_existing_exports_file(app, &lib, size)
                                .map_or_else(|| "null".to_string(), |f| f.absolute_path());
                        log.append_msg(&format!(
                            "Unable to locate symbol [{sym_name}] in [{exports_file}]. \
                             Please verify the version is correct."
                        ));
                        continue;
                    };
                    let address = ext_loc.get_address();
                    if let Some(location) = external_location_mut(em, &ext_loc) {
                        if let Err(e) =
                            location.set_location(exp_sym.name(), address, SourceType::Imported)
                        {
                            log.append_msg(&format!("Error creating label: {e}"));
                        }
                    }
                    exp_sym
                }
            };

            let purge_size = exp_sym.purge(app);
            // no purge size for 64-bit programs
            let is_not_32_bit = size > 32;
            if purge_size == -1 || purge_size < -1024 || purge_size > 1024 || is_not_32_bit {
                continue;
            }

            let has_no_return = exp_sym.has_no_return(app);

            // Create or get external function
            if let Some(location) = external_location_mut(em, &ext_loc) {
                if let Some(ext_func) = location.create_function_mut() {
                    ext_func.set_stack_purge_size(purge_size);
                    if has_no_return {
                        ext_func.set_no_return(true);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Re-resolves `location` through `em` as a mutable reference, which the `Arc` its iterator hands
/// out cannot provide. `None` if the location has no symbol to look it back up by, or if `em`
/// does not support mutable lookup; see the module docs.
fn external_location_mut<'a>(
    em: &'a mut dyn crate::program::model::symbol::ExternalManager,
    location: &Arc<dyn ExternalLocation>,
) -> std::option::Option<&'a mut dyn ExternalLocation> {
    em.get_external_location_mut(location.get_symbol()?)
}

/// `isVersionMatch(DomainObject, LibrarySymbolTable, MessageLog)`: whether the program's recorded
/// product version is the one the `.exports` file was generated from.
///
/// Java takes a `DomainObject`; this takes the `Program` its only caller has, since both members
/// it reads (`getOptions`/`getName`) are on `Program` too.
fn is_version_match(p: &dyn Program, symtab: &LibrarySymbolTable, log: &dyn MessageLog) -> bool {
    let version = get_rid_of_version_alias(Some(symtab.get_version()));

    let options = p.get_options(PROGRAM_INFO);
    // `getString(name, null)`: the ported `Options` has no nullable-default `get_string`, and
    // `get_value_as_string` answers the same "is it set, and to what" question.
    let program_version =
        get_rid_of_version_alias(options.get_value_as_string("ProductVersion").as_deref());

    let Some(program_version) = program_version else {
        return false;
    };

    // Java's `programVersion.equalsIgnoreCase(null)` is simply false.
    let matches = version.as_deref().is_some_and(|v| program_version.eq_ignore_ascii_case(v));

    if !matches {
        log.append_msg(&format!(
            "Library version mismatch in .exports file for {}",
            Program::get_name(p)
        ));
        log.append_msg(&format!(
            "   expected {program_version} but was {}",
            version.as_deref().unwrap_or("null")
        ));
    }
    matches
}

/// `getRidOfVersionAlias(String)`: the version with any parenthesized alias stripped off, trimmed.
fn get_rid_of_version_alias(version: std::option::Option<&str>) -> std::option::Option<String> {
    let version = version?;
    Some(match version.find('(') {
        None => version.trim().to_string(),
        Some(alias_open_paren_position) => version[..alias_open_paren_position].trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The smallest thing that can be an [`AbstractOrdinalSupportLoader`]: a subclass that adds
    /// nothing, like the ones in Java that only override `getName`/`findSupportedLoadSpecs`.
    struct TestOrdinalLoader;
    impl AbstractOrdinalSupportLoader for TestOrdinalLoader {}

    /// [`MessageLog`] that records what was appended, since the placeholder discards it.
    #[derive(Default)]
    struct RecordingLog {
        messages: Mutex<Vec<String>>,
    }

    impl MessageLog for RecordingLog {
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
    }

    /// An [`Option`] holding a value of the wrong type for the ordinal-lookup option.
    struct StringValuedOption(&'static str);

    impl Option for StringValuedOption {
        fn get_name(&self) -> String {
            self.0.to_string()
        }

        fn get_value(&self) -> Box<dyn std::any::Any> {
            Box::new("not a boolean".to_string())
        }
    }

    #[test]
    fn default_options_append_the_ordinal_lookup_option() {
        let options = TestOrdinalLoader.get_default_options(Vec::new());

        assert_eq!(options.len(), 1);
        let option = &options[0];
        assert_eq!(option.get_name(), "Perform Library Ordinal Lookup");
        // Java: .value(ORDINAL_LOOKUP_OPTION_DEFAULT), which is true.
        assert_eq!(option.get_value().downcast_ref::<bool>(), Some(&true));
        // Java: .commandLineArgument(createArg("-ordinalLookup")), i.e. COMMAND_LINE_ARG_PREFIX.
        assert_eq!(option.get_arg(), "-loader-ordinalLookup");
        // Java: .stateKey(Loader.OPTIONS_PROJECT_SAVE_STATE_KEY).
        assert_eq!(option.get_state_key(), "LOADER_OPTIONS");
    }

    #[test]
    fn default_options_are_appended_after_the_inherited_ones() {
        let base: Vec<Box<dyn Option>> = vec![Box::new(StringValuedOption("Inherited Option"))];
        let options = TestOrdinalLoader.get_default_options(base);

        let names: Vec<String> = options.iter().map(|o| o.get_name()).collect();
        assert_eq!(names, vec!["Inherited Option", "Perform Library Ordinal Lookup"]);
    }

    #[test]
    fn validate_options_rejects_only_a_mistyped_ordinal_lookup_option() {
        // Java opens with `if (options != null)`, so a null list validates.
        assert_eq!(TestOrdinalLoader.validate_options(None), None);

        // The option this class owns, holding a String instead of a Boolean.
        let mistyped: Vec<Box<dyn Option>> =
            vec![Box::new(StringValuedOption(ORDINAL_LOOKUP_OPTION_NAME))];
        assert_eq!(
            TestOrdinalLoader.validate_options(Some(&mistyped)),
            Some("Invalid type for option: Perform Library Ordinal Lookup".to_string())
        );

        // A differently-named option of the same type is not this class's business.
        let unrelated: Vec<Box<dyn Option>> = vec![Box::new(StringValuedOption("Some Other Option"))];
        assert_eq!(TestOrdinalLoader.validate_options(Some(&unrelated)), None);

        // The correctly-typed option validates.
        let well_typed = TestOrdinalLoader.get_default_options(Vec::new());
        assert_eq!(TestOrdinalLoader.validate_options(Some(&well_typed)), None);
    }

    #[test]
    fn ordinal_lookup_defaults_to_on_and_follows_the_option() {
        // Java: OptionUtils.getOption(name, options, ORDINAL_LOOKUP_OPTION_DEFAULT), default true.
        assert!(should_perform_ordinal_lookup(&[]));
        assert!(TestOrdinalLoader.should_search_all_paths(&[]));

        let on = TestOrdinalLoader.get_default_options(Vec::new());
        assert!(should_perform_ordinal_lookup(&on));

        let off: Vec<Box<dyn Option>> = vec![new_boolean(ORDINAL_LOOKUP_OPTION_NAME)
            .value(Box::new(false))
            .build()];
        assert!(!should_perform_ordinal_lookup(&off));
        assert!(!TestOrdinalLoader.should_search_all_paths(&off));
    }

    #[test]
    fn version_alias_is_stripped_and_trimmed() {
        // Java: no '(' -> version.trim().
        assert_eq!(get_rid_of_version_alias(Some(" 5.100.2566 ")), Some("5.100.2566".to_string()));
        // Java: substring(0, aliasOpenParenPosition).trim().
        assert_eq!(
            get_rid_of_version_alias(Some("5.100.2566 (release build)")),
            Some("5.100.2566".to_string())
        );
        // A leading alias leaves nothing behind.
        assert_eq!(get_rid_of_version_alias(Some("(alias) 5.1")), Some(String::new()));
        // Java: null in, null out.
        assert_eq!(get_rid_of_version_alias(None), None);
    }

    #[test]
    fn post_load_program_fixups_is_skipped_when_ordinal_lookup_is_off() {
        let log = RecordingLog::default();
        let monitor = crate::util::task::DummyMonitor;
        let off: Vec<Box<dyn Option>> = vec![new_boolean(ORDINAL_LOOKUP_OPTION_NAME)
            .value(Box::new(false))
            .build()];

        // With no programs to walk this can only observe the early return, which is the point:
        // an `Application` is never resolved and nothing is logged.
        struct NoApplication;
        impl Application for NoApplication {
            fn application_layout(
                &self,
            ) -> Box<dyn crate::framework::seam_stubs::ApplicationLayoutLike> {
                unreachable!("ordinal lookup is off, so no exports file is ever resolved")
            }

            fn current_platform(&self) -> Box<dyn crate::framework::platform::Platform> {
                unreachable!("ordinal lookup is off, so no exports file is ever resolved")
            }
        }

        TestOrdinalLoader
            .post_load_program_fixups(&mut [], &NoApplication, &off, &log, &monitor)
            .unwrap();
        assert!(log.messages.lock().unwrap().is_empty());
    }
}
