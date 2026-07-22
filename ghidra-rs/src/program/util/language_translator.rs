use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::Program;
use crate::program::seam_stubs::RegisterValue;
use crate::util::task::TaskMonitor;

/// Translation capabilities used by `Program::set_language` when converting a program from one
/// language to another or from one version to another.
///
/// Port of `ghidra.program.util.LanguageTranslator`. The Java `ExtensionPoint` marker interface
/// (used for classpath discovery) has no Rust equivalent and is dropped.
///
/// Explicit translator implementations should not instantiate `Language`, `AddressSpace`, or
/// `Register` objects until [`LanguageTranslator::is_valid`] is invoked.
pub trait LanguageTranslator {
    /// Validates the translator to complete initialization and ensure language compatibility.
    /// This method is invoked by the (not yet ported) `LanguageTranslatorFactory` before handing
    /// out this translator.
    fn is_valid(&self) -> bool;

    /// Returns the old language.
    ///
    /// # Panics
    /// Implementations may panic if the instance has not been validated (see
    /// [`LanguageTranslator::is_valid`]).
    fn get_old_language(&self) -> Arc<dyn Language>;

    /// Returns the new language.
    fn get_new_language(&self) -> Arc<dyn Language>;

    /// Returns the old language ID.
    fn get_old_language_id(&self) -> LanguageID;

    /// Returns the new language ID.
    fn get_new_language_id(&self) -> LanguageID;

    /// Returns the old language version.
    fn get_old_version(&self) -> i32;

    /// Returns the new language version.
    fn get_new_version(&self) -> i32;

    /// Translates a BASE address space (overlay spaces are not handled).
    ///
    /// # Arguments
    /// * `old_space_name` - old space name
    ///
    /// # Returns
    /// The corresponding address space in the new language, or `None` if no correspondence
    /// exists.
    fn get_new_address_space(&self, old_space_name: &str) -> Option<Arc<AddressSpace>>;

    /// Gets the old register at the specified `old_addr`. Returns `None` if the specified
    /// address is offcut within the register. The smallest register will be returned which is
    /// greater than or equal to the specified size.
    ///
    /// # Arguments
    /// * `old_addr` - old register address
    /// * `size` - minimum register size
    fn get_old_register(&self, old_addr: &Address, size: i32) -> Option<RegisterRef>;

    /// Gets the largest old register which contains the specified `old_addr`, which may be
    /// offcut.
    fn get_old_register_containing(&self, old_addr: &Address) -> Option<RegisterRef>;

    /// Returns the old processor context register, or `None` if not defined.
    fn get_old_context_register(&self) -> Option<RegisterRef>;

    /// Finds the new register which corresponds to the specified old register.
    fn get_new_register(&self, old_reg: &RegisterRef) -> Option<RegisterRef>;

    /// Returns the new processor context register, or `None` if not defined.
    fn get_new_context_register(&self) -> Option<RegisterRef>;

    /// Gets the translated register value.
    ///
    /// # Arguments
    /// * `old_value` - old register value
    ///
    /// # Returns
    /// The new register value, or `None` if the register is not mapped.
    ///
    /// See [`LanguageTranslator::is_value_translation_required`].
    fn get_new_register_value(&self, old_value: &dyn RegisterValue) -> Option<Box<dyn RegisterValue>>;

    /// Returns `true` if register value translation is required for the program context.
    fn is_value_translation_required(&self, old_reg: &RegisterRef) -> bool;

    /// Obtains the new compiler specification ID given the old compiler spec ID.
    fn get_new_compiler_spec_id(&self, old_compiler_spec_id: &CompilerSpecID) -> CompilerSpecID;

    /// Gets a compiler spec suitable for use with the old language. The compiler spec returned
    /// is intended for upgrade use only prior to the language set and may be based upon compiler
    /// conventions specified in the new compiler spec returned by
    /// [`Language::get_compiler_spec_by_id`] given the same compiler spec ID.
    ///
    /// # Errors
    /// Returns [`CompilerSpecNotFoundException`] if the new compiler spec cannot be found based
    /// upon the translator's mappings.
    fn get_old_compiler_spec(
        &self,
        old_compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException>;

    /// Invoked after a program language upgrade has completed. Implementations may examine or
    /// modify the final re-disassembled program to address more complex language upgrades. This
    /// method is only invoked on the latest translator, meaning all complex multi-version
    /// post-upgrade concerns must factor in the complete language transition. The program's
    /// language information will still reflect the original pre-upgrade state, and if the
    /// program is undergoing a schema version upgrade as well, certain complex upgrades may not
    /// have been completed (e.g., function and variable changes). Program modifications should
    /// be restricted to instruction and instruction context changes only.
    ///
    /// # Arguments
    /// * `program` - the program being upgraded
    /// * `old_language` - the oldest language involved in the current upgrade translation (this
    ///   is passed since this is the only fixup invocation which must handle any relevant fixup
    ///   complexities when transitioning from the specified old language)
    /// * `monitor` - task monitor
    ///
    /// # Errors
    /// Returns an error if a problem occurs during the post-upgrade fixup, or if the operation is
    /// cancelled via `monitor` (surfaced as a
    /// [`CancelledException`](crate::util::exception::CancelledException)).
    fn fixup_instructions(
        &self,
        program: &mut dyn Program,
        old_language: &dyn Language,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::register::Register;
    use std::collections::HashMap;

    /// A minimal translator that only knows how to rename a couple of address spaces and
    /// registers, proving the trait is object-safe and that real translation logic can be driven
    /// through a `dyn LanguageTranslator`.
    struct RenamingTranslator {
        space_map: HashMap<String, Arc<AddressSpace>>,
        register_map: HashMap<String, RegisterRef>,
    }

    impl LanguageTranslator for RenamingTranslator {
        fn is_valid(&self) -> bool {
            true
        }

        fn get_old_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this test")
        }

        fn get_new_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this test")
        }

        fn get_old_language_id(&self) -> LanguageID {
            LanguageID::new("8051:BE:16:default").unwrap()
        }

        fn get_new_language_id(&self) -> LanguageID {
            LanguageID::new("8051:BE:16:default").unwrap()
        }

        fn get_old_version(&self) -> i32 {
            1
        }

        fn get_new_version(&self) -> i32 {
            2
        }

        fn get_new_address_space(&self, old_space_name: &str) -> Option<Arc<AddressSpace>> {
            self.space_map.get(old_space_name).cloned()
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

        fn get_new_register(&self, old_reg: &RegisterRef) -> Option<RegisterRef> {
            self.register_map.get(old_reg.borrow().name()).cloned()
        }

        fn get_new_context_register(&self) -> Option<RegisterRef> {
            None
        }

        fn get_new_register_value(&self, _old_value: &dyn RegisterValue) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn is_value_translation_required(&self, old_reg: &RegisterRef) -> bool {
            self.get_new_register(old_reg).is_none()
        }

        fn get_new_compiler_spec_id(&self, old_compiler_spec_id: &CompilerSpecID) -> CompilerSpecID {
            old_compiler_spec_id.clone()
        }

        fn get_old_compiler_spec(
            &self,
            old_compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(
                &self.get_old_language_id(),
                old_compiler_spec_id,
            ))
        }

        fn fixup_instructions(
            &self,
            _program: &mut dyn Program,
            _old_language: &dyn Language,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    fn make_translator() -> RenamingTranslator {
        let old_ram = AddressSpace::new("ram", 16, 1, AddressSpaceType::Ram, 0);
        let new_ram = AddressSpace::new("RAM", 16, 1, AddressSpaceType::Ram, 0);
        let mut space_map = HashMap::new();
        space_map.insert(old_ram.name().to_string(), new_ram);

        let reg_space = AddressSpace::new("register", 16, 1, AddressSpaceType::Register, 1);
        let old_reg = Register::new("R0", "", reg_space.address(0x0), 1, false, Register::TYPE_NONE);
        let new_reg = Register::new("EAX", "", reg_space.address(0x0), 1, false, Register::TYPE_NONE);
        let mut register_map = HashMap::new();
        register_map.insert(old_reg.borrow().name().to_string(), new_reg);

        RenamingTranslator { space_map, register_map }
    }

    #[test]
    fn trait_object_translates_address_space_by_name() {
        let translator: Box<dyn LanguageTranslator> = Box::new(make_translator());

        let translated = translator.get_new_address_space("ram").unwrap();
        assert_eq!(translated.name(), "RAM");

        assert!(translator.get_new_address_space("unknown").is_none());
    }

    #[test]
    fn trait_object_translates_register_by_name_and_flags_untranslatable() {
        let translator = make_translator();
        let reg_space = AddressSpace::new("register", 16, 1, AddressSpaceType::Register, 1);
        let old_r0 = Register::new("R0", "", reg_space.address(0x0), 1, false, Register::TYPE_NONE);
        let unmapped = Register::new("R1", "", reg_space.address(0x1), 1, false, Register::TYPE_NONE);

        let new_reg = translator.get_new_register(&old_r0).unwrap();
        assert_eq!(new_reg.borrow().name(), "EAX");
        assert!(!translator.is_value_translation_required(&old_r0));

        assert!(translator.get_new_register(&unmapped).is_none());
        assert!(translator.is_value_translation_required(&unmapped));
    }

    #[test]
    fn get_old_compiler_spec_reports_not_found() {
        let translator = make_translator();
        let spec_id = CompilerSpecID::new(Some("gcc"));
        let result = translator.get_old_compiler_spec(&spec_id);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected CompilerSpecNotFoundException"),
        };
        assert!(err.message().contains("gcc"));
    }
}
