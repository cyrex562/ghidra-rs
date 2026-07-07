use crate::program::database::ProgramDB;

/// Generates a named [`ProgramDB`] instance for merge/diff test scenarios.
///
/// Implementors supply a factory method that constructs a fully-populated
/// `ProgramDB` under the given name. Used by merge-test harnesses that need
/// reproducible program fixtures.
pub trait MergeProgramGenerator {
    fn generate_program(
        &self,
        program_name: &str,
    ) -> Result<ProgramDB, Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::pcode::PackedDecode;
    use std::sync::Arc;

    struct StubGenerator {
        language: Arc<SleighLanguage>,
    }

    impl MergeProgramGenerator for StubGenerator {
        fn generate_program(
            &self,
            program_name: &str,
        ) -> Result<ProgramDB, Box<dyn std::error::Error>> {
            Ok(ProgramDB::new(program_name.to_string(), self.language.clone())?)
        }
    }

    fn make_language() -> Arc<SleighLanguage> {
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        data.extend_from_slice(&[0xA0, 0x80 | 33]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(
            vec![],
        ));
        let decoder = PackedDecode::new(factory, data);
        Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap())
    }

    #[test]
    fn test_generate_program_returns_named_program() {
        let generator = StubGenerator {
            language: make_language(),
        };
        let program = generator.generate_program("my_prog").unwrap();
        use crate::program::model::listing::Program;
        assert_eq!(program.get_name(), "my_prog");
    }

    #[test]
    fn test_generate_program_different_names() {
        let language = make_language();
        let generator = StubGenerator {
            language: language.clone(),
        };
        let p1 = generator.generate_program("alpha").unwrap();
        let p2 = generator.generate_program("beta").unwrap();
        use crate::program::model::listing::Program;
        assert_eq!(p1.get_name(), "alpha");
        assert_eq!(p2.get_name(), "beta");
    }
}
