use std::fmt;
use std::sync::Arc;

use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::seam_stubs::{LanguageNotFoundException, LanguageTranslatorFactory, OldLanguageFactory};
use crate::program::util::language_translator::LanguageTranslator;
use crate::util::exception::VersionException;
use crate::util::msg::Msg;

/// A [`VersionException`] carrying the extra old-language/translator information needed to
/// upgrade a program from an older language version.
///
/// Port of `ghidra.program.model.lang.LanguageVersionException`. Promoted to a trait (rather
/// than a concrete struct) because it sits at a dependency-cycle cut point: the type is
/// referenced by not-yet-ported database/program code that must not be forced to depend on the
/// concrete `Language`/`LanguageTranslator` implementations. Implementors expose the accessors
/// through trait objects (`Arc<dyn Language>` / `Arc<dyn LanguageTranslator>`) instead.
///
/// The Java class's two `static` factory methods, [`check`] and [`check_for_language_change`],
/// are ported as free functions in this module rather than trait methods, since they construct
/// new instances (`Self: Sized`) and reach through the not-yet-ported `OldLanguageFactory` /
/// `LanguageTranslatorFactory` singletons (see [`crate::program::seam_stubs::OldLanguageFactory`]
/// / [`crate::program::seam_stubs::LanguageTranslatorFactory`]); those factories are passed in as
/// parameters instead of being looked up via a static getter.
pub trait LanguageVersionException: std::error::Error {
    /// The wrapped [`VersionException`] (message, upgradeable flag, version indicator).
    fn version_exception(&self) -> &VersionException;

    /// Old language stub if language translation required.
    fn get_old_language(&self) -> Option<Arc<dyn Language>>;

    /// Old language upgrade translator if language translation required.
    fn get_language_translator(&self) -> Option<Arc<dyn LanguageTranslator>>;
}

/// Default [`LanguageVersionException`] implementation, constructed via [`check`] or
/// [`check_for_language_change`] (or directly via [`DefaultLanguageVersionException::new`] /
/// [`DefaultLanguageVersionException::with_language_translator`]).
pub struct DefaultLanguageVersionException {
    version_exception: VersionException,
    old_language: Option<Arc<dyn Language>>,
    language_translator: Option<Arc<dyn LanguageTranslator>>,
}

impl DefaultLanguageVersionException {
    /// Constructs a language version exception.
    ///
    /// `upgradable` true indicates that an upgrade is possible.
    pub fn new(msg: impl Into<String>, upgradable: bool) -> Self {
        let version_indicator = if upgradable {
            VersionException::OLDER_VERSION
        } else {
            VersionException::UNKNOWN_VERSION
        };
        Self {
            version_exception: VersionException::with_message_and_version(
                msg,
                version_indicator,
                upgradable,
            ),
            old_language: None,
            language_translator: None,
        }
    }

    /// Constructs a major upgradeable language version exception.
    pub fn with_language_translator(
        old_language: Arc<dyn Language>,
        language_translator: Arc<dyn LanguageTranslator>,
    ) -> Self {
        Self {
            version_exception: VersionException::with_upgradeable(true),
            old_language: Some(old_language),
            language_translator: Some(language_translator),
        }
    }

    /// Overrides the detail message carried by the wrapped [`VersionException`].
    pub fn set_detail_message(&mut self, message: impl Into<String>) {
        self.version_exception.set_detail_message(message);
    }
}

impl LanguageVersionException for DefaultLanguageVersionException {
    fn version_exception(&self) -> &VersionException {
        &self.version_exception
    }

    fn get_old_language(&self) -> Option<Arc<dyn Language>> {
        self.old_language.clone()
    }

    fn get_language_translator(&self) -> Option<Arc<dyn LanguageTranslator>> {
        self.language_translator.clone()
    }
}

impl fmt::Debug for DefaultLanguageVersionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultLanguageVersionException")
            .field("version_exception", &self.version_exception)
            .field("has_old_language", &self.old_language.is_some())
            .field("has_language_translator", &self.language_translator.is_some())
            .finish()
    }
}

impl fmt::Display for DefaultLanguageVersionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.version_exception, f)
    }
}

impl std::error::Error for DefaultLanguageVersionException {}

/// Check `language` against required version information. If not a match or upgradeable, an
/// `Err(LanguageNotFoundException)` is returned. If an upgradeable exception is returned, a major
/// version change will also include the appropriate old-language stub and translator required to
/// facilitate a language upgrade.
///
/// Returns `Ok(None)` if `language` matches the required version, otherwise an upgradeable
/// [`DefaultLanguageVersionException`].
///
/// Port of `LanguageVersionException.check`. `old_language_factory` and `translator_factory`
/// stand in for the Java method's `OldLanguageFactory.getOldLanguageFactory()` /
/// `LanguageTranslatorFactory.getLanguageTranslatorFactory()` singleton lookups.
pub fn check(
    old_language_factory: &dyn OldLanguageFactory,
    translator_factory: &dyn LanguageTranslatorFactory,
    language: &Arc<dyn Language>,
    language_version: i32,
    language_minor_version: i32,
) -> Result<Option<DefaultLanguageVersionException>, LanguageNotFoundException> {
    let language_id = language.get_language_id();

    if language.get_version() > language_version {
        let new_language = Arc::clone(language);

        let old_language = match old_language_factory.get_old_language(&language_id, language_version) {
            Some(old_language) => old_language,
            None => {
                let msg = format!(
                    "Old language specification not found: {} (Version {}), translation not possible",
                    language_id, language_version
                );
                Msg::error("LanguageVersionException", &msg);
                return Ok(Some(DefaultLanguageVersionException::new(msg, false)));
            }
        };

        let language_upgrade_translator = match translator_factory
            .get_language_translator_for_languages(&old_language, &new_language)
        {
            Some(translator) => translator,
            None => {
                return Err(LanguageNotFoundException(format!(
                    "Language not found for '{}' (Ver {}.{} -> {}.{}) language version translation not supported",
                    language_id,
                    language_version,
                    language_minor_version,
                    new_language.get_version(),
                    new_language.get_minor_version(),
                )));
            }
        };

        return Ok(Some(DefaultLanguageVersionException::with_language_translator(
            old_language,
            language_upgrade_translator,
        )));
    } else if language.get_version() == language_version && language_minor_version < 0 {
        // Minor version ignored - considered as match if major number matches
        return Ok(None);
    } else if language.get_version() == language_version
        && language.get_minor_version() > language_minor_version
    {
        // Minor version change - translator not needed
        let from_ver = format!("{}.{}", language_version, language_minor_version);
        let to_ver = format!("{}.{}", language_version, language.get_minor_version());
        return Ok(Some(DefaultLanguageVersionException::new(
            format!("Minor language change {} -> {}", from_ver, to_ver),
            true,
        )));
    } else if language.get_minor_version() != language_minor_version
        || language.get_version() != language_version
    {
        return Err(LanguageNotFoundException(format!(
            "Language version (V{}.{} or later) required for '{}'",
            language_version, language_minor_version, language_id
        )));
    }
    Ok(None) // language matches
}

/// Determine if a missing language resulting in a language-not-found error can be upgraded to a
/// replacement language via a language translation.
///
/// Port of `LanguageVersionException.checkForLanguageChange`. `translator_factory` stands in for
/// the Java method's `LanguageTranslatorFactory.getLanguageTranslatorFactory()` singleton lookup.
///
/// # Errors
/// Returns `e` unchanged if a language translation is not available.
pub fn check_for_language_change(
    translator_factory: &dyn LanguageTranslatorFactory,
    e: LanguageNotFoundException,
    language_id: &LanguageID,
    language_version: i32,
) -> Result<DefaultLanguageVersionException, LanguageNotFoundException> {
    let language_upgrade_translator = match translator_factory
        .get_language_translator_for_version(language_id, language_version)
    {
        Some(translator) => translator,
        None => return Err(e),
    };

    let old_language = language_upgrade_translator.get_old_language();
    let old_language_id = old_language.get_language_id();
    let new_lang_name = language_upgrade_translator.get_new_language().get_language_id();

    let mut ve = DefaultLanguageVersionException::with_language_translator(
        old_language,
        language_upgrade_translator,
    );
    let message = if old_language_id == new_lang_name {
        "Program requires a processor language version change".to_string()
    } else {
        format!("Program requires a processor language change to: {}", new_lang_name)
    };
    ve.set_detail_message(message);
    Ok(ve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressFactory, AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
use crate::program::model::mem::MemBuffer;
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    struct MockProcessor;
    impl Processor for MockProcessor {}

    struct MockLanguage {
        id: LanguageID,
        version: i32,
        minor_version: i32,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            self.id.clone()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_version(&self) -> i32 {
            self.version
        }
        fn get_minor_version(&self) -> i32 {
            self.minor_version
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            mock_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            mock_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
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
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct MockLanguageTranslator {
        old_language: Arc<dyn Language>,
        new_language: Arc<dyn Language>,
    }

    impl LanguageTranslator for MockLanguageTranslator {
        fn is_valid(&self) -> bool {
            true
        }
        fn get_old_language(&self) -> Arc<dyn Language> {
            Arc::clone(&self.old_language)
        }
        fn get_new_language(&self) -> Arc<dyn Language> {
            Arc::clone(&self.new_language)
        }
        fn get_old_language_id(&self) -> LanguageID {
            self.old_language.get_language_id()
        }
        fn get_new_language_id(&self) -> LanguageID {
            self.new_language.get_language_id()
        }
        fn get_old_version(&self) -> i32 {
            self.old_language.get_version()
        }
        fn get_new_version(&self) -> i32 {
            self.new_language.get_version()
        }
        fn get_new_address_space(&self, _old_space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_old_register(&self, _old_addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_old_register_containing(&self, _old_addr: &Address) -> Option<RegisterRef> {
            None
        }
        fn get_old_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_new_register(&self, _old_reg: &RegisterRef) -> Option<RegisterRef> {
            None
        }
        fn get_new_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_new_register_value(
            &self,
            _old_value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn is_value_translation_required(&self, _old_reg: &RegisterRef) -> bool {
            false
        }
        fn get_new_compiler_spec_id(
            &self,
            old_compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> crate::program::model::lang::compiler_spec_id::CompilerSpecID {
            old_compiler_spec_id.clone()
        }
        fn get_old_compiler_spec(
            &self,
            old_compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(
                &self.get_old_language_id(),
                old_compiler_spec_id,
            ))
        }
        fn fixup_instructions(
            &self,
            _program: &mut dyn crate::program::model::listing::Program,
            _old_language: &dyn Language,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    struct FixedOldLanguageFactory(Option<Arc<dyn Language>>);
    impl OldLanguageFactory for FixedOldLanguageFactory {
        fn get_old_language(&self, _language_id: &LanguageID, _language_version: i32) -> Option<Arc<dyn Language>> {
            self.0.as_ref().map(Arc::clone)
        }
    }

    struct FixedTranslatorFactory(Option<Arc<dyn LanguageTranslator>>);
    impl LanguageTranslatorFactory for FixedTranslatorFactory {
        fn get_language_translator_for_languages(
            &self,
            _old_language: &Arc<dyn Language>,
            _new_language: &Arc<dyn Language>,
        ) -> Option<Arc<dyn LanguageTranslator>> {
            self.0.as_ref().map(Arc::clone)
        }
        fn get_language_translator_for_version(
            &self,
            _language_id: &LanguageID,
            _language_version: i32,
        ) -> Option<Arc<dyn LanguageTranslator>> {
            self.0.as_ref().map(Arc::clone)
        }
    }

    fn lang(id: &str, version: i32, minor_version: i32) -> Arc<dyn Language> {
        Arc::new(MockLanguage {
            id: LanguageID::new(id).unwrap(),
            version,
            minor_version,
        })
    }

    #[test]
    fn matching_version_returns_none() {
        let language = lang("x86:LE:32:default", 2, 1);
        let old_factory = FixedOldLanguageFactory(None);
        let translator_factory = FixedTranslatorFactory(None);
        let result = check(&old_factory, &translator_factory, &language, 2, 1).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn matching_major_ignored_minor_returns_none() {
        let language = lang("x86:LE:32:default", 2, 5);
        let old_factory = FixedOldLanguageFactory(None);
        let translator_factory = FixedTranslatorFactory(None);
        let result = check(&old_factory, &translator_factory, &language, 2, -1).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn mismatched_version_without_translator_errors() {
        let language = lang("x86:LE:32:default", 2, 0);
        let old_factory = FixedOldLanguageFactory(None);
        let translator_factory = FixedTranslatorFactory(None);
        let err = check(&old_factory, &translator_factory, &language, 3, 0).unwrap_err();
        assert!(err.to_string().contains("x86:LE:32:default"));
    }

    #[test]
    fn minor_version_downgrade_is_upgradeable_without_translator() {
        let language = lang("x86:LE:32:default", 2, 5);
        let old_factory = FixedOldLanguageFactory(None);
        let translator_factory = FixedTranslatorFactory(None);
        let result = check(&old_factory, &translator_factory, &language, 2, 1)
            .unwrap()
            .expect("expected upgradeable exception");
        assert!(result.version_exception().is_upgradable());
        assert!(result.get_old_language().is_none());
        assert!(result.get_language_translator().is_none());
    }

    #[test]
    fn major_upgrade_with_translator_carries_old_language() {
        let new_language = lang("x86:LE:32:default", 2, 0);
        let old_language = lang("x86:LE:32:default", 1, 3);
        let translator: Arc<dyn LanguageTranslator> = Arc::new(MockLanguageTranslator {
            old_language: Arc::clone(&old_language),
            new_language: Arc::clone(&new_language),
        });

        let old_factory = FixedOldLanguageFactory(Some(Arc::clone(&old_language)));
        let translator_factory = FixedTranslatorFactory(Some(Arc::clone(&translator)));

        let result = check(&old_factory, &translator_factory, &new_language, 1, 3)
            .unwrap()
            .expect("expected upgradeable exception");
        assert!(result.version_exception().is_upgradable());
        assert_eq!(
            result.get_old_language().unwrap().get_language_id(),
            old_language.get_language_id()
        );
        assert!(result.get_language_translator().is_some());
    }

    #[test]
    fn major_upgrade_without_old_language_is_not_upgradeable() {
        let new_language = lang("x86:LE:32:default", 2, 0);
        let old_factory = FixedOldLanguageFactory(None);
        let translator_factory = FixedTranslatorFactory(None);

        let result = check(&old_factory, &translator_factory, &new_language, 1, 0)
            .unwrap()
            .expect("expected exception describing the missing old language");
        assert!(!result.version_exception().is_upgradable());
    }

    #[test]
    fn major_upgrade_without_translator_errors() {
        let new_language = lang("x86:LE:32:default", 2, 0);
        let old_language = lang("x86:LE:32:default", 1, 0);
        let old_factory = FixedOldLanguageFactory(Some(old_language));
        let translator_factory = FixedTranslatorFactory(None);

        let err = check(&old_factory, &translator_factory, &new_language, 1, 0).unwrap_err();
        assert!(err.to_string().contains("translation not supported"));
    }

    #[test]
    fn check_for_language_change_without_translator_returns_original_error() {
        let translator_factory = FixedTranslatorFactory(None);
        let original = LanguageNotFoundException("original error".to_string());
        let id = LanguageID::new("x86:LE:32:default").unwrap();
        let err = check_for_language_change(&translator_factory, original, &id, 1).unwrap_err();
        assert_eq!(err.to_string(), "original error");
    }

    #[test]
    fn check_for_language_change_with_translator_sets_detail_message() {
        let old_language = lang("x86:LE:32:default", 1, 0);
        let new_language = lang("arm:LE:32:v8", 2, 0);
        let translator: Arc<dyn LanguageTranslator> = Arc::new(MockLanguageTranslator {
            old_language: Arc::clone(&old_language),
            new_language: Arc::clone(&new_language),
        });
        let translator_factory = FixedTranslatorFactory(Some(translator));
        let id = LanguageID::new("x86:LE:32:default").unwrap();

        let ve = check_for_language_change(
            &translator_factory,
            LanguageNotFoundException("unused".to_string()),
            &id,
            1,
        )
        .unwrap();

        assert_eq!(
            ve.version_exception().detail_message(),
            Some("Program requires a processor language change to: arm:LE:32:v8")
        );
        assert_eq!(
            ve.get_old_language().unwrap().get_language_id(),
            old_language.get_language_id()
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let ve: Box<dyn LanguageVersionException> =
            Box::new(DefaultLanguageVersionException::new("bad version", true));
        assert!(ve.version_exception().is_upgradable());
        assert!(ve.get_old_language().is_none());
    }
}
