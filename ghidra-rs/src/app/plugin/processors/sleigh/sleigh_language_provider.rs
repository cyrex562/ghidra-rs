//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageProvider`.
//!
//! In Java this is a concrete class implementing `LanguageProvider`, backed by a singleton that
//! discovers `.ldefs` files across the application's resource search path and lazily
//! compiles/loads the `SleighLanguage`s they describe. It was selected as a dependency-cycle
//! cut-point, so its instance surface is promoted to the [`SleighLanguageProvider`] trait here,
//! with [`LanguageProvider`] as a supertrait (the overridden `hadLoadFailure`/`isLanguageLoaded`/
//! `getLanguage`/`getLanguageDescriptions` members already live there).
//!
//! Dropped entirely:
//! - The static singleton accessor `getSleighLanguageProvider()` and the private/package
//!   constructors that scan `Application.findFilesByExtensionInApplication(".ldefs")` and parse
//!   them via `SleighLanguageValidator`/`XmlPullParser`. Singleton lifecycle and filesystem/XML
//!   discovery are not part of the instance contract this trait exists to describe, mirroring the
//!   scope decision already made for [`SleighLanguageFile`](super::sleigh_language_file)'s static
//!   factories.
//! - The private nested `LanguageRec` bookkeeping (load/failure caching) and the SAX
//!   `ErrorHandler` factory methods (`throwingErrorHandler`/`loggingErrorHandler`): these are
//!   implementation details of the concrete Java class, not part of the abstract contract.
//!
//! Kept as free items (not trait methods, since they are `static` in Java): the
//! [`LANGUAGE_LOCK_TIMEOUT_PROPNAME`] system-property name and the [`language_lock_timeout`]
//! accessor for the sla-file lock timeout duration described in `SleighLanguageProvider`'s Javadoc
//! (default 60 seconds, overridable via that property).
//!
//! `getLanguageDescription(LanguageID)` (singular, returning the Sleigh-specific description) and
//! the package-private `unloadLanguage(LanguageID)` are genuine additions over the
//! [`LanguageProvider`] supertrait, so they become trait methods here.

use std::time::Duration;

use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_provider::LanguageProvider;

use super::sleigh_language_description::SleighLanguageDescription;

/// System property that overrides [`language_lock_timeout`]'s duration, in milliseconds. Port of
/// `SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT_PROPNAME`.
pub const LANGUAGE_LOCK_TIMEOUT_PROPNAME: &str =
    "ghidra.app.plugin.processors.sleigh.SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT_MS";

const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 60;

/// Timeout used when trying to acquire the sla file lock (default 60 seconds, overridable via
/// [`LANGUAGE_LOCK_TIMEOUT_PROPNAME`]). Port of `SleighLanguageProvider.LANGUAGE_LOCK_TIMEOUT`,
/// turned into a function since Rust has no direct equivalent of a JVM-startup-time-evaluated
/// `static final` reading `System.getProperty`.
pub fn language_lock_timeout() -> Duration {
    if let Ok(override_ms) = std::env::var(LANGUAGE_LOCK_TIMEOUT_PROPNAME) {
        if let Ok(ms) = override_ms.parse::<u64>() {
            return Duration::from_millis(ms);
        }
    }
    Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS)
}

/// Searches resources for Sleigh spec files and provides [`SleighLanguageDescription`]s (and,
/// via the [`LanguageProvider`] supertrait, the languages themselves) for those specifications.
/// Port of the instance contract of `ghidra.app.plugin.processors.sleigh.SleighLanguageProvider`
/// (see the module docs for what is out of scope).
pub trait SleighLanguageProvider: LanguageProvider {
    /// Returns the [`SleighLanguageDescription`] of the specified language, or `None` if no such
    /// language is known to this provider. Port of
    /// `SleighLanguageProvider.getLanguageDescription(LanguageID)`.
    fn get_sleigh_language_description(
        &self,
        language_id: &LanguageID,
    ) -> Option<Box<dyn SleighLanguageDescription>>;

    /// Unloads the specified language, if loaded, so it will be re-instantiated the next time it
    /// is requested. Port of the package-private `SleighLanguageProvider.unloadLanguage(LanguageID)`.
    fn unload_language(&self, language_id: &LanguageID);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::seam_stubs::LanguageNotFoundException;
    use crate::util::task::TaskMonitor;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockSleighLanguageDescription {
        language_id: LanguageID,
    }

    impl LanguageDescription for MockSleighLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            self.language_id.clone()
        }

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            struct MockProcessor;
            impl crate::program::seam_stubs::Processor for MockProcessor {}
            Box::new(MockProcessor)
        }

        fn get_endian(&self) -> Endian {
            Endian::Little
        }

        fn get_instruction_endian(&self) -> Endian {
            Endian::Little
        }

        fn get_size(&self) -> i32 {
            32
        }

        fn get_variant(&self) -> String {
            "default".to_string()
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_description(&self) -> String {
            "Mock Sleigh x86 32-bit little endian".to_string()
        }

        fn is_deprecated(&self) -> bool {
            false
        }

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            vec![]
        }

        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            Err(
                crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException::new(
                    &self.get_language_id(),
                    compiler_spec_id,
                ),
            )
        }

        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    impl SleighLanguageDescription for MockSleighLanguageDescription {
        fn get_truncated_space_names(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn get_truncated_space_size(&self, _space_name: &str) -> Option<i32> {
            None
        }

        fn get_defs_file(&self) -> Option<&crate::generic::jar::resource_file::ResourceFile> {
            None
        }

        fn set_defs_file(&mut self, _defs_file: Option<crate::generic::jar::resource_file::ResourceFile>) {
        }

        fn get_spec_file(&self) -> Option<&crate::generic::jar::resource_file::ResourceFile> {
            None
        }

        fn set_spec_file(&mut self, _spec_file: Option<crate::generic::jar::resource_file::ResourceFile>) {
        }

        fn get_manual_index_file(&self) -> Option<&crate::generic::jar::resource_file::ResourceFile> {
            None
        }

        fn set_manual_index_file(
            &mut self,
            _manual_index_file: Option<crate::generic::jar::resource_file::ResourceFile>,
        ) {
        }

        fn get_language_file(
            &self,
        ) -> Option<&dyn crate::app::plugin::processors::sleigh::sleigh_language_file::SleighLanguageFile>
        {
            None
        }

        fn set_language_file(
            &mut self,
            _language_file: Option<
                Box<dyn crate::app::plugin::processors::sleigh::sleigh_language_file::SleighLanguageFile>,
            >,
        ) {
        }
    }

    /// Mock provider tracking loaded/unloaded state per language id, proving object-safety of the
    /// full [`LanguageProvider`] + [`SleighLanguageProvider`] combination and exercising real
    /// `unload_language`/`get_sleigh_language_description` behavior.
    struct MockSleighLanguageProvider {
        loaded: RefCell<HashMap<LanguageID, bool>>,
        had_failure: bool,
    }

    impl LanguageProvider for MockSleighLanguageProvider {
        fn get_language_with_monitor(
            &self,
            language_id: &LanguageID,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn Language>>, LanguageNotFoundException> {
            if *self.loaded.borrow().get(language_id).unwrap_or(&false) {
                Ok(None)
            } else {
                Err(LanguageNotFoundException(format!(
                    "Language not found for '{}'",
                    language_id
                )))
            }
        }

        fn get_language_descriptions(&self) -> Vec<Box<dyn LanguageDescription>> {
            self.loaded
                .borrow()
                .keys()
                .map(|id| {
                    Box::new(MockSleighLanguageDescription {
                        language_id: id.clone(),
                    }) as Box<dyn LanguageDescription>
                })
                .collect()
        }

        fn had_load_failure(&self) -> bool {
            self.had_failure
        }

        fn is_language_loaded(&self, language_id: &LanguageID) -> bool {
            *self.loaded.borrow().get(language_id).unwrap_or(&false)
        }
    }

    impl SleighLanguageProvider for MockSleighLanguageProvider {
        fn get_sleigh_language_description(
            &self,
            language_id: &LanguageID,
        ) -> Option<Box<dyn SleighLanguageDescription>> {
            if self.loaded.borrow().contains_key(language_id) {
                Some(Box::new(MockSleighLanguageDescription {
                    language_id: language_id.clone(),
                }))
            } else {
                None
            }
        }

        fn unload_language(&self, language_id: &LanguageID) {
            self.loaded.borrow_mut().insert(language_id.clone(), false);
        }
    }

    fn mock(id: &LanguageID) -> MockSleighLanguageProvider {
        let mut loaded = HashMap::new();
        loaded.insert(id.clone(), true);
        MockSleighLanguageProvider {
            loaded: RefCell::new(loaded),
            had_failure: false,
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        let provider: Box<dyn SleighLanguageProvider> = Box::new(mock(&id));

        assert!(!provider.had_load_failure());
        assert!(provider.is_language_loaded(&id));
        assert!(provider.get_sleigh_language_description(&id).is_some());

        let unknown = LanguageID::new("arm:LE:32:default").unwrap();
        assert!(provider.get_sleigh_language_description(&unknown).is_none());
    }

    #[test]
    fn unload_language_flips_loaded_state() {
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        let provider = mock(&id);
        assert!(provider.is_language_loaded(&id));

        provider.unload_language(&id);

        assert!(!provider.is_language_loaded(&id));
        assert!(provider.get_language(&id).is_err());
    }

    #[test]
    fn language_lock_timeout_defaults_to_sixty_seconds() {
        // NOTE: does not exercise the LANGUAGE_LOCK_TIMEOUT_PROPNAME override path, since that
        // would require mutating process-global env state shared with other tests in this binary.
        std::env::remove_var(LANGUAGE_LOCK_TIMEOUT_PROPNAME);
        assert_eq!(language_lock_timeout(), Duration::from_secs(60));
    }
}
