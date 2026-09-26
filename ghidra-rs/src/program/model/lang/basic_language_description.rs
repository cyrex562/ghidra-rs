use crate::program::model::lang::language_description::LanguageDescription;

/// Port of `ghidra.program.model.lang.BasicLanguageDescription`, a concrete implementation of
/// [`LanguageDescription`] that adds no public API beyond the interface itself (its only other
/// members are constructors and the `Object` overrides `equals`/`hashCode`/`toString`).
///
/// It was selected as a dependency-cycle cut-point. Since it introduces no new methods, its
/// contract is captured entirely by requiring [`LanguageDescription`] as a supertrait -- every
/// `LanguageDescription` implementation automatically satisfies this trait via the blanket impl
/// below, mirroring how any `BasicLanguageDescription` instance in Java is usable wherever a
/// `LanguageDescription` is expected. `equals`/`toString` are reproduced as default methods so
/// their semantics stay available to callers working through this trait.
pub trait BasicLanguageDescription: LanguageDescription {
    /// Port of `BasicLanguageDescription.equals(Object)`: two descriptions are equal iff their
    /// `LanguageID`s are equal.
    fn language_description_eq(&self, other: &dyn LanguageDescription) -> bool {
        self.get_language_id() == other.get_language_id()
    }

    /// Port of `BasicLanguageDescription.toString()`: `"{processor}/{endian}/{size}/{variant}"`.
    fn to_display_string(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.get_processor().name(),
            self.get_endian(),
            self.get_size(),
            self.get_variant()
        )
    }
}

impl<T: LanguageDescription + ?Sized> BasicLanguageDescription for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::Processor;

    struct MockProcessor(&'static str);
    impl Processor for MockProcessor {
        fn name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }

        fn get_compiler_spec_name(&self) -> String {
            "GCC".to_string()
        }

        fn get_source(&self) -> String {
            "gcc.cspec".to_string()
        }
    }

    struct MockLanguageDescription {
        language_id: LanguageID,
    }

    impl LanguageDescription for MockLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            self.language_id.clone()
        }

        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor("x86"))
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
            "Mock x86 32-bit little endian".to_string()
        }

        fn is_deprecated(&self) -> bool {
            false
        }

        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }

        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            if compiler_spec_id == &CompilerSpecID::new(Some("gcc")) {
                Ok(Box::new(MockCompilerSpecDescription))
            } else {
                Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
            }
        }

        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    #[test]
    fn usable_as_trait_object_via_blanket_impl() {
        let description: Box<dyn BasicLanguageDescription> = Box::new(MockLanguageDescription {
            language_id: LanguageID::new("x86:LE:32:default").unwrap(),
        });

        assert_eq!(description.get_language_id().get_id_as_string(), "x86:LE:32:default");
        assert_eq!(description.to_display_string(), "x86/little/32/default");
    }

    #[test]
    fn language_description_eq_compares_by_language_id_only() {
        let a = MockLanguageDescription {
            language_id: LanguageID::new("x86:LE:32:default").unwrap(),
        };
        let b = MockLanguageDescription {
            language_id: LanguageID::new("x86:LE:32:default").unwrap(),
        };
        let c = MockLanguageDescription {
            language_id: LanguageID::new("arm:LE:32:default").unwrap(),
        };

        assert!(a.language_description_eq(&b));
        assert!(!a.language_description_eq(&c));
    }
}
