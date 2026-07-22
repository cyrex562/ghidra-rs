use std::sync::Arc;

use crate::filesystem::gfilesystem::g_file::GFile;
use crate::framework::model::domain_object::DomainObjectConsumer;
use crate::program::model::lang::LanguageService;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// [`GFileSystem`](super::g_file_system::GFileSystem) add-on trait that allows a filesystem to
/// publish the fact that it supports an import feature allowing the caller to import binaries
/// directly into Ghidra without going through a `Loader`.
///
/// Mirrors `ghidra.formats.gfilesystem.GFileSystemProgramProvider`. Implementing filesystems
/// implement both `GFileSystem` and this trait; callers probe for support with a downcast
/// rather than Java's `instanceof`.
///
/// `FS` and `Fsrl` are the same free type parameters used by [`GFile`] -- the concrete
/// filesystem and FSRL types -- kept as trait-level generics (rather than tied to `Self`) so
/// this trait stays object-safe.
pub trait GFileSystemProgramProvider<FS, Fsrl> {
    /// NOTE: only override this method if you cannot provide an input stream to the internal
    /// files of this filesystem. Be sure to register the given consumer on the program.
    ///
    /// Returns a program for the given file.
    ///
    /// # Arguments
    /// * `file` - the file to convert into a program
    /// * `language_service` - the language service for locating languages and compiler
    ///   specifications
    /// * `monitor` - a task monitor
    /// * `consumer` - the consumer for the program to be returned
    ///
    /// # Errors
    /// Returns an error if the file cannot be converted into a program.
    fn get_program(
        &self,
        file: &dyn GFile<FS, Fsrl>,
        language_service: &dyn LanguageService,
        monitor: &dyn TaskMonitor,
        consumer: DomainObjectConsumer,
    ) -> Result<Arc<dyn Program>, Box<dyn std::error::Error>>;

    /// Returns `true` if this `GFileSystem` can convert the specified `GFile` instance into a
    /// Ghidra `Program`.
    ///
    /// # Arguments
    /// * `file` - `GFile` file or directory instance
    ///
    /// Returns `true` if calls to [`get_program`](Self::get_program) will be able to convert
    /// the file into a program.
    fn can_provide_program(&self, file: &dyn GFile<FS, Fsrl>) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::{
        ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair, LanguageCompilerSpecQuery,
        LanguageNotFoundException, Processor,
    };
    use crate::util::exception::CancelledException;

    struct MockProgram {
        name: String,
    }
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockFs;
    struct MockFsrl;

    struct MockFile {
        path: String,
        name: String,
    }

    impl GFile<MockFs, MockFsrl> for MockFile {
        fn get_filesystem(&self) -> &MockFs {
            unimplemented!()
        }
        fn get_fsrl(&self) -> &MockFsrl {
            unimplemented!()
        }
        fn get_parent_file(&self) -> Option<&dyn GFile<MockFs, MockFsrl>> {
            None
        }
        fn get_path(&self) -> &str {
            &self.path
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn is_directory(&self) -> bool {
            false
        }
        fn get_length(&self) -> i64 {
            42
        }
        fn get_listing(&self) -> std::io::Result<Vec<Box<dyn GFile<MockFs, MockFsrl>>>> {
            Ok(vec![])
        }
    }

    struct DummyMonitor {
        cancelled: bool,
    }

    impl TaskMonitor for DummyMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.cancelled {
                Err(CancelledException::default())
            } else {
                Ok(())
            }
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            -1
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    /// Provider that can only import files whose name ends in `.bin`, mimicking a filesystem
    /// that supports importing some but not all of its contents directly.
    struct BinOnlyProvider;

    impl GFileSystemProgramProvider<MockFs, MockFsrl> for BinOnlyProvider {
        fn get_program(
            &self,
            file: &dyn GFile<MockFs, MockFsrl>,
            _language_service: &dyn LanguageService,
            monitor: &dyn TaskMonitor,
            _consumer: DomainObjectConsumer,
        ) -> Result<Arc<dyn Program>, Box<dyn std::error::Error>> {
            monitor.check_cancelled()?;
            if !self.can_provide_program(file) {
                return Err(format!("cannot import {}", file.get_name()).into());
            }
            Ok(Arc::new(MockProgram { name: file.get_name().to_string() }))
        }

        fn can_provide_program(&self, file: &dyn GFile<MockFs, MockFsrl>) -> bool {
            file.get_name().ends_with(".bin")
        }
    }

    fn monitor() -> DummyMonitor {
        DummyMonitor { cancelled: false }
    }

    struct NoopLanguageService;
    impl LanguageService for NoopLanguageService {
        fn get_language(
            &self,
            _language_id: &LanguageID,
        ) -> Result<Box<dyn Language>, LanguageNotFoundException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_default_language(
            &self,
            _processor: &dyn Processor,
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
            _processor: &dyn Processor,
            _endianness: Option<Endian>,
            _size: Option<i32>,
            _variant: Option<&str>,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }

        fn get_language_compiler_spec_pairs(
            &self,
            _query: &LanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            Vec::new()
        }

        fn get_language_compiler_spec_pairs_external(
            &self,
            _query: &ExternalLanguageCompilerSpecQuery,
        ) -> Vec<LanguageCompilerSpecPair> {
            Vec::new()
        }

        fn get_language_descriptions_for_processor(
            &self,
            _processor: &dyn Processor,
        ) -> Vec<Box<dyn LanguageDescription>> {
            Vec::new()
        }
    }

    #[test]
    fn can_provide_program_checks_extension() {
        let provider = BinOnlyProvider;
        let importable = MockFile { path: "/a.bin".into(), name: "a.bin".into() };
        let not_importable = MockFile { path: "/a.txt".into(), name: "a.txt".into() };

        assert!(provider.can_provide_program(&importable));
        assert!(!provider.can_provide_program(&not_importable));
    }

    #[test]
    fn get_program_succeeds_for_supported_file() {
        let provider = BinOnlyProvider;
        let file = MockFile { path: "/a.bin".into(), name: "a.bin".into() };
        let consumer: DomainObjectConsumer = Arc::new(42i32);

        let program = provider
            .get_program(&file, &NoopLanguageService as &dyn LanguageService, &monitor(), consumer)
            .expect("supported file should convert");

        assert_eq!(Program::get_name(&*program), "a.bin");
    }

    #[test]
    fn get_program_fails_for_unsupported_file() {
        let provider = BinOnlyProvider;
        let file = MockFile { path: "/a.txt".into(), name: "a.txt".into() };
        let consumer: DomainObjectConsumer = Arc::new(42i32);

        let result = provider.get_program(
            &file,
            &NoopLanguageService as &dyn LanguageService,
            &monitor(),
            consumer,
        );
        let err = result.map(|_| ()).unwrap_err();

        assert!(err.to_string().contains("a.txt"));
    }

    #[test]
    fn provider_as_trait_object() {
        let provider: Box<dyn GFileSystemProgramProvider<MockFs, MockFsrl>> = Box::new(BinOnlyProvider);
        let file = MockFile { path: "/z.bin".into(), name: "z.bin".into() };

        assert!(provider.can_provide_program(&file));
    }
}
