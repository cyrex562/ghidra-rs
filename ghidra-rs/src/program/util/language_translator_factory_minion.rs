use crate::program::util::language_translator::LanguageTranslator;

/// A single contributor of [`LanguageTranslator`]s to a `LanguageTranslatorFactory` (not yet
/// ported). Each minion is responsible for discovering or constructing whatever translators it
/// knows how to provide, e.g. by scanning a directory of upgrade specifications or by hand-coding
/// a fixed set of translators.
///
/// Port of `ghidra.program.util.LanguageTranslatorFactoryMinion`. The Java `Collection` return
/// type becomes a `Vec` of trait objects, matching how other multi-result accessors in this crate
/// are ported.
pub trait LanguageTranslatorFactoryMinion {
    /// Returns the collection of language translators this minion contributes.
    fn get_language_translators(&self) -> Vec<Box<dyn LanguageTranslator>>;
}

#[cfg(test)]
mod tests {
    use super::*;
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
    use std::sync::Arc;

    /// A translator that reports fixed old/new language versions, just enough to distinguish it
    /// from another translator instance in the minion below.
    struct FixedVersionTranslator {
        old_version: i32,
        new_version: i32,
    }

    impl LanguageTranslator for FixedVersionTranslator {
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
            self.old_version
        }

        fn get_new_version(&self) -> i32 {
            self.new_version
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

        fn get_new_register_value(&self, _old_value: &dyn RegisterValue) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn is_value_translation_required(&self, _old_reg: &RegisterRef) -> bool {
            false
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

    /// A minion that hands back a fixed, hand-coded set of translators, proving the trait is
    /// object-safe and can be driven through a `dyn LanguageTranslatorFactoryMinion`.
    struct FixedSetMinion;

    impl LanguageTranslatorFactoryMinion for FixedSetMinion {
        fn get_language_translators(&self) -> Vec<Box<dyn LanguageTranslator>> {
            vec![
                Box::new(FixedVersionTranslator { old_version: 1, new_version: 2 }),
                Box::new(FixedVersionTranslator { old_version: 2, new_version: 3 }),
            ]
        }
    }

    #[test]
    fn trait_object_reports_contributed_translators() {
        let minion: Box<dyn LanguageTranslatorFactoryMinion> = Box::new(FixedSetMinion);

        let translators = minion.get_language_translators();

        assert_eq!(translators.len(), 2);
        assert_eq!(translators[0].get_old_version(), 1);
        assert_eq!(translators[0].get_new_version(), 2);
        assert_eq!(translators[1].get_old_version(), 2);
        assert_eq!(translators[1].get_new_version(), 3);
    }

    #[test]
    fn empty_minion_reports_no_translators() {
        struct EmptyMinion;
        impl LanguageTranslatorFactoryMinion for EmptyMinion {
            fn get_language_translators(&self) -> Vec<Box<dyn LanguageTranslator>> {
                Vec::new()
            }
        }

        let minion = EmptyMinion;
        assert!(minion.get_language_translators().is_empty());
    }
}
