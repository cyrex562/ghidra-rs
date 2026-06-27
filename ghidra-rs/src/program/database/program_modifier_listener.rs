use crate::program::database::ProgramDB;

/// Modifies programs in preparation for a merge test.
///
/// Implementors supply two mutation callbacks — one for the "latest" program
/// and one for the "private" (local) program — matching the two-branch model
/// used by Ghidra's merge-test harnesses.
pub trait ProgramModifierListener {
    fn modify_latest(&self, program: &mut ProgramDB) -> Result<(), Box<dyn std::error::Error>>;
    fn modify_private(&self, program: &mut ProgramDB) -> Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::pcode::PackedDecode;
    use std::sync::Arc;

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

    struct RecordingModifier {
        latest_called: std::cell::Cell<bool>,
        private_called: std::cell::Cell<bool>,
    }

    impl RecordingModifier {
        fn new() -> Self {
            Self {
                latest_called: std::cell::Cell::new(false),
                private_called: std::cell::Cell::new(false),
            }
        }
    }

    impl ProgramModifierListener for RecordingModifier {
        fn modify_latest(
            &self,
            _program: &mut ProgramDB,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.latest_called.set(true);
            Ok(())
        }

        fn modify_private(
            &self,
            _program: &mut ProgramDB,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.private_called.set(true);
            Ok(())
        }
    }

    #[test]
    fn test_modify_latest_is_called() {
        let lang = make_language();
        let mut program = ProgramDB::new("latest".to_string(), lang).unwrap();
        let modifier = RecordingModifier::new();
        modifier.modify_latest(&mut program).unwrap();
        assert!(modifier.latest_called.get());
        assert!(!modifier.private_called.get());
    }

    #[test]
    fn test_modify_private_is_called() {
        let lang = make_language();
        let mut program = ProgramDB::new("private".to_string(), lang).unwrap();
        let modifier = RecordingModifier::new();
        modifier.modify_private(&mut program).unwrap();
        assert!(modifier.private_called.get());
        assert!(!modifier.latest_called.get());
    }

    #[test]
    fn test_both_methods_callable_independently() {
        let lang = make_language();
        let mut latest_prog = ProgramDB::new("latest".to_string(), lang.clone()).unwrap();
        let mut private_prog = ProgramDB::new("private".to_string(), lang).unwrap();
        let modifier = RecordingModifier::new();
        modifier.modify_latest(&mut latest_prog).unwrap();
        modifier.modify_private(&mut private_prog).unwrap();
        assert!(modifier.latest_called.get());
        assert!(modifier.private_called.get());
    }
}
