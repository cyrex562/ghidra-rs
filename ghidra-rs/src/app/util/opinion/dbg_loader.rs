//! Port of `ghidra.app.util.opinion.DbgLoader`.
//!
//! An opinion service for processing Microsoft DBG files: standalone Codeview/COFF debug-symbol
//! files that get "added" to an already-loaded PE `Program`.
//!
//! # Departures from the Java class
//!
//! * `DbgLoader extends AbstractPeDebugLoader` (in turn `AbstractOrdinalSupportLoader`, in turn
//!   `AbstractProgramLoader`), which implement the bulk of the `Loader` interface (program
//!   creation, transaction management, options plumbing, `getTier()`/`getTierPriority()`, ...) and
//!   are not ported. `DbgLoader.java` itself only overrides `findSupportedLoadSpecs`, `load`,
//!   `getName`, and `supportsLoadIntoProgram`, so -- like
//!   [`XmlLoader`](crate::app::util::opinion::xml_loader::XmlLoader) and
//!   [`ElfLoader`](crate::app::util::opinion::elf_loader::ElfLoader) -- this port models just that
//!   overridden surface as inherent methods on a standalone struct, rather than implementing the
//!   [`Loader`](crate::app::util::opinion::loader::Loader) trait (which would additionally require
//!   the inherited machinery this class never defines).
//! * `QueryOpinionService.query(String, String, String)` resolves the process-wide `Application`
//!   singleton (`DefaultLanguageService`'s singleton accessor was likewise dropped when it was
//!   ported); [`find_supported_load_specs`](DbgLoader::find_supported_load_specs) takes explicit
//!   `&dyn Application`/`&dyn LanguageService` parameters instead, mirroring the identical
//!   substitution in [`ElfLoader::find_supported_load_specs`](crate::app::util::opinion::elf_loader::ElfLoader::find_supported_load_specs).
//!   Java's third `query` argument (`null`, standing in for "no secondary key") becomes `""`: see
//!   [`query_opinion_service::query`](crate::app::util::opinion::query_opinion_service::query)'s
//!   masking fallback, which treats an unparseable secondary key exactly like Java's null does.
//! * `PeLoader.PE_NAME` (`PeLoader` is not ported) becomes the local [`PE_NAME`] constant.
//! * `AbstractPeDebugLoader.processDebug` -- together with the `PortableExecutable`/`NTHeader`/
//!   `FileHeader`/PE-`SectionHeader` parsing `DbgLoader.load` performs to build its
//!   `sectionToAddress` argument -- is a large unported subsystem (there is no way yet to parse a
//!   `NTHeader` from bytes). Both halves are bundled into the single placeholder
//!   [`abstract_pe_debug_loader::process_debug`](crate::app::seam_stubs::abstract_pe_debug_loader::process_debug),
//!   which panics until that subsystem lands; see its docs. `RandomAccessByteProvider` -- the one
//!   piece of that setup [`load`](DbgLoader::load) can perform for real (reopening the parent
//!   program's backing file) -- is still opened for real first, so a missing/unreadable parent
//!   file surfaces its own `io::Error` exactly as Java's `new RandomAccessByteProvider(File)`
//!   would, before falling into the placeholder.
//! * `ImporterSettings` (the `Loader` trait's parameter type, not modeled per the first bullet) is
//!   unpacked into the individual pieces `load` actually reads: `provider`, `options`, `monitor`.

use std::cell::RefCell;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;

use crate::app::seam_stubs::{abstract_pe_debug_loader, LoadSpec, Option as LoaderOption, RandomAccessByteProvider};
use crate::app::util::opinion::query_opinion_service;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::seam_stubs::SeparateDebugHeader;
use crate::framework::application::Application;
use crate::program::model::lang::language_service::LanguageService;
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

/// `DbgLoader.DBG_NAME`.
pub const DBG_NAME: &str = "Debug Symbols (DBG)";

/// `DbgLoader.MIN_BYTE_LENGTH`.
const MIN_BYTE_LENGTH: u64 = 46;

/// Stands in for the unported `PeLoader.PE_NAME`, which `DbgLoader.load` compares
/// `prog.getExecutableFormat()` against.
const PE_NAME: &str = "Portable Executable (PE)";

/// An opinion service for processing Microsoft DBG files.
///
/// Port of `ghidra.app.util.opinion.DbgLoader`.
pub struct DbgLoader;

impl Default for DbgLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl DbgLoader {
    pub fn new() -> Self {
        DbgLoader
    }

    /// `DbgLoader.findSupportedLoadSpecs(ByteProvider)`. See the module docs for why `app`/
    /// `language_service` are explicit parameters.
    pub fn find_supported_load_specs(
        &self,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        app: &dyn Application,
        language_service: &dyn LanguageService,
    ) -> io::Result<Vec<LoadSpec>> {
        let mut load_specs = Vec::new();
        if provider.borrow_mut().length()? < MIN_BYTE_LENGTH {
            return Ok(load_specs);
        }

        let debug = SeparateDebugHeader::new(provider)?;
        if debug.signature == SeparateDebugHeader::IMAGE_SEPARATE_DEBUG_SIGNATURE {
            // `Integer.toUnsignedLong(debug.getImageBase())`.
            let image_base = debug.image_base as u32 as i64;
            let machine_name = debug.machine_name();
            for result in query_opinion_service::query(
                app,
                language_service,
                self.get_name(),
                &machine_name,
                "",
            ) {
                load_specs.push(LoadSpec::from_query_result(image_base, &result));
            }
            if load_specs.is_empty() {
                load_specs.push(LoadSpec::without_language_compiler_spec(image_base, true));
            }
        }

        Ok(load_specs)
    }

    /// `DbgLoader.load(Program, ImporterSettings)`. See the module docs for why `settings` is
    /// unpacked into `provider`/`options`/`monitor`, and for what
    /// [`abstract_pe_debug_loader::process_debug`] does and does not model.
    pub fn load(
        &self,
        prog: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        options: &[Box<dyn LoaderOption>],
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        if prog.get_executable_format() != PE_NAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Loading of DBG file may only be 'added' to existing {PE_NAME} Program"),
            ));
        }

        let debug = SeparateDebugHeader::new(provider)?;

        let parent_path = PathBuf::from(prog.get_executable_path());
        let provider2 = RandomAccessByteProvider::new(parent_path)?;

        abstract_pe_debug_loader::process_debug(debug.get_parser(), prog, options, monitor);

        // Java's `finally { if (provider2 != null) provider2.close(); }`. `close()` is a no-op
        // (see its docs) -- Rust's `File` releases its descriptor when `provider2` drops -- but
        // the call is still made to mirror Java's control flow.
        provider2.close()
    }

    /// `DbgLoader.getName()`.
    pub fn get_name(&self) -> &'static str {
        DBG_NAME
    }

    /// `DbgLoader.supportsLoadIntoProgram()`.
    pub fn supports_load_into_program(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::{
        ExternalLanguageCompilerSpecQuery, LanguageCompilerSpecPair, LanguageCompilerSpecQuery,
        LanguageNotFoundException, Processor,
    };

    /// A [`ByteProvider`] over an in-memory byte buffer, used to feed synthetic
    /// `IMAGE_SEPARATE_DEBUG_HEADER` fixtures to [`DbgLoader::find_supported_load_specs`].
    struct BufferProvider {
        bytes: Vec<u8>,
    }

    impl ByteProvider for BufferProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"));
            }
            Ok(self.bytes[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            self.bytes[index as usize] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            self.bytes[start..start + values.len()].copy_from_slice(values);
            Ok(())
        }
    }

    fn provider_with(bytes: Vec<u8>) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::new(RefCell::new(BufferProvider { bytes }))
    }

    /// Builds a well-formed `IMAGE_SEPARATE_DEBUG_HEADER` with zero sections/exported names and
    /// an empty (zero-size) debug directory, matching the fixed 46-byte layout
    /// `SeparateDebugHeader` reads (signature/flags/machine/characteristics, 8 `int`s, and a
    /// 2-element reserved `int` array).
    fn synthetic_header(signature: i16, machine: i16, image_base: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&signature.to_le_bytes());
        bytes.extend_from_slice(&0i16.to_le_bytes()); // flags
        bytes.extend_from_slice(&machine.to_le_bytes());
        bytes.extend_from_slice(&0i16.to_le_bytes()); // characteristics
        bytes.extend_from_slice(&0i32.to_le_bytes()); // timeDateStamp
        bytes.extend_from_slice(&0i32.to_le_bytes()); // checkSum
        bytes.extend_from_slice(&image_base.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes()); // sizeOfImage
        bytes.extend_from_slice(&0i32.to_le_bytes()); // numberOfSections
        bytes.extend_from_slice(&0i32.to_le_bytes()); // exportedNamesSize
        bytes.extend_from_slice(&0i32.to_le_bytes()); // debugDirectorySize
        bytes.extend_from_slice(&0i32.to_le_bytes()); // sectionAlignment
        bytes.extend_from_slice(&0i32.to_le_bytes()); // reserved[0]
        bytes.extend_from_slice(&0i32.to_le_bytes()); // reserved[1]
        bytes
    }

    /// `Application` with no `.opinion` files, so `find_supported_load_specs` always exercises
    /// the "no matches" fallback branch. Mirrors the identical mock in
    /// [`elf_loader`](crate::app::util::opinion::elf_loader)'s tests.
    struct MockApplication;

    impl crate::framework::seam_stubs::ApplicationLayoutLike for MockApplication {
        fn application_properties(
            &self,
        ) -> &dyn crate::framework::application_properties::ApplicationProperties {
            unimplemented!("not exercised by this smoke test")
        }
        fn application_installation_dir(
            &self,
        ) -> std::option::Option<&crate::generic::jar::ResourceFile> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl Application for MockApplication {
        fn application_layout(&self) -> Box<dyn crate::framework::seam_stubs::ApplicationLayoutLike> {
            Box::new(MockApplication)
        }
        fn current_platform(&self) -> Box<dyn crate::framework::platform::Platform> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockLanguageService;

    #[allow(deprecated)]
    impl LanguageService for MockLanguageService {
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
            _endianness: std::option::Option<Endian>,
            _size: std::option::Option<i32>,
            _variant: std::option::Option<&str>,
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
    fn constants_match_java() {
        assert_eq!(DBG_NAME, "Debug Symbols (DBG)");
        assert_eq!(MIN_BYTE_LENGTH, 46);
        let loader = DbgLoader::new();
        assert_eq!(loader.get_name(), DBG_NAME);
        assert!(loader.supports_load_into_program());
    }

    #[test]
    fn too_short_provider_yields_no_load_specs() {
        let loader = DbgLoader::new();
        let provider = provider_with(vec![0u8; 10]);
        let specs = loader
            .find_supported_load_specs(&provider, &MockApplication, &MockLanguageService)
            .unwrap();
        assert!(specs.is_empty());
    }

    #[test]
    fn wrong_signature_yields_no_load_specs() {
        let loader = DbgLoader::new();
        // A well-sized but non-`0x4944`-signed header.
        let provider = provider_with(synthetic_header(0, 0x014c, 0x0040_0000u32 as i32));
        let specs = loader
            .find_supported_load_specs(&provider, &MockApplication, &MockLanguageService)
            .unwrap();
        assert!(specs.is_empty());
    }

    #[test]
    fn valid_header_falls_back_to_unresolved_load_spec_with_unsigned_image_base() {
        let loader = DbgLoader::new();
        // IMAGE_FILE_MACHINE_I386 = 0x014c; image base high bit set, to exercise the
        // `Integer.toUnsignedLong` conversion.
        let image_base = -0x7FFF_FFFFi32; // 0x80000001 as unsigned
        let provider = provider_with(synthetic_header(
            SeparateDebugHeader::IMAGE_SEPARATE_DEBUG_SIGNATURE,
            0x014c,
            image_base,
        ));

        let specs = loader
            .find_supported_load_specs(&provider, &MockApplication, &MockLanguageService)
            .unwrap();

        assert_eq!(specs.len(), 1);
        assert!(specs[0].language_compiler_spec.is_none());
        assert!(specs[0].requires_language_compiler_spec);
        assert_eq!(specs[0].desired_image_base, image_base as u32 as i64);
    }

    #[test]
    fn separate_debug_header_reads_machine_name_via_machine_name_port() {
        let provider = provider_with(synthetic_header(
            SeparateDebugHeader::IMAGE_SEPARATE_DEBUG_SIGNATURE,
            0x014c,
            0,
        ));
        let header = SeparateDebugHeader::new(&provider).unwrap();
        assert_eq!(header.machine_name(), crate::format::pe::machine_name::get_name_i16(0x014c));
        // Zero sections/exported names/debug-directory size: `get_parser()` is `Some`, but the
        // parser itself found no `IMAGE_DEBUG_DIRECTORY` entries.
        let parser = header.get_parser().expect("valid header parses a debug directory");
        assert!(parser.get_debug_directories().is_empty());
    }

    /// Every `Program` method besides the three overridden below has a default implementation
    /// (see that trait's definition), so only those three need modeling for this smoke test.
    struct NonPeProgram;

    impl Program for NonPeProgram {
        fn get_name(&self) -> String {
            "NonPeProgram".to_string()
        }
        fn get_language_id(&self) -> String {
            String::new()
        }
        fn get_executable_format(&self) -> String {
            "Executable and Linking Format (ELF)".to_string()
        }
    }
    impl crate::framework::model::DomainObject for NonPeProgram {}

    #[test]
    fn load_rejects_a_non_pe_program() {
        let loader = DbgLoader::new();
        let mut program = NonPeProgram;
        let provider = provider_with(synthetic_header(0, 0, 0));
        let err = loader
            .load(&mut program, &provider, &[], &crate::util::task::DummyMonitor)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("Portable Executable (PE)"));
    }
}
