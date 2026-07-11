use crate::program::model::lang::Language;
use crate::program::model::listing::CodeUnit;
use crate::util::classfinder::ExtensionPoint;
use std::error::Error;

/// Marker trait for external disassembler implementations.
///
/// External disassemblers provide disassembly capabilities for code units
/// using external tools or libraries. This trait is an extension point that allows
/// pluggable implementations of disassembly functionality.
///
/// Java equivalent: `ghidra.app.util.disassemble.ExternalDisassembler`
pub trait ExternalDisassembler: ExtensionPoint {
    /// Gets the disassembly string for the given code unit.
    ///
    /// # Arguments
    /// * `cu` - The code unit to disassemble
    ///
    /// # Returns
    /// The disassembly string for the code unit
    ///
    /// # Errors
    /// Returns an error if the disassembly cannot be performed
    fn get_disassembly(&self, cu: &dyn CodeUnit) -> Result<String, Box<dyn Error>>;

    /// Gets the disassembly display prefix for the given code unit.
    ///
    /// The prefix is typically used to display additional information about
    /// the disassembly, such as address or comments.
    ///
    /// # Arguments
    /// * `cu` - The code unit to get the prefix for
    ///
    /// # Returns
    /// The display prefix string for the code unit
    ///
    /// # Errors
    /// Returns an error if the prefix cannot be retrieved
    fn get_disassembly_display_prefix(&self, cu: &dyn CodeUnit) -> Result<String, Box<dyn Error>>;

    /// Gets the disassembly of a byte sequence for a specified language.
    ///
    /// This method allows disassembly of raw bytes without requiring an existing code unit.
    ///
    /// # Arguments
    /// * `language` - The language context for disassembly
    /// * `is_big_endian` - Whether bytes are in big-endian format
    /// * `address` - The address at which the bytes are located
    /// * `byte_string` - The bytes to disassemble
    ///
    /// # Returns
    /// The disassembly string for the byte sequence
    ///
    /// # Errors
    /// Returns an error if the disassembly cannot be performed
    fn get_disassembly_of_bytes(
        &self,
        language: &dyn Language,
        is_big_endian: bool,
        address: i64,
        byte_string: &[u8],
    ) -> Result<String, Box<dyn Error>>;

    /// Checks if this disassembler supports the given language.
    ///
    /// # Arguments
    /// * `language` - The language to check for support
    ///
    /// # Returns
    /// `true` if the language is supported, `false` otherwise
    fn is_supported_language(&self, language: &dyn Language) -> bool;

    /// Cleans up resources used by this disassembler.
    ///
    /// This method should be called when the disassembler is no longer needed
    /// to free any system resources that may have been allocated.
    fn destroy(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCodeUnit;

    impl CodeUnit for MockCodeUnit {
        fn get_min_address(&self) -> crate::program::model::address::Address {
            todo!()
        }

        fn get_max_address(&self) -> crate::program::model::address::Address {
            todo!()
        }

        fn get_address(&self) -> crate::program::model::address::Address {
            todo!()
        }

        fn contains(&self, address: &crate::program::model::address::Address) -> bool {
            todo!()
        }

        fn size(&self) -> i64 {
            todo!()
        }

        fn read_byte(&self, offset: i64) -> Result<u8, Box<dyn Error>> {
            todo!()
        }

        fn read_bytes(&self, data: &mut [u8], offset: i64) -> Result<(), Box<dyn Error>> {
            todo!()
        }
    }

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> &str {
            "mock"
        }
    }

    struct TestDisassembler {
        supported: bool,
    }

    impl ExtensionPoint for TestDisassembler {}

    impl ExternalDisassembler for TestDisassembler {
        fn get_disassembly(
            &self,
            _cu: &dyn CodeUnit,
        ) -> Result<String, Box<dyn Error>> {
            Ok("test disassembly".to_string())
        }

        fn get_disassembly_display_prefix(
            &self,
            _cu: &dyn CodeUnit,
        ) -> Result<String, Box<dyn Error>> {
            Ok("test prefix".to_string())
        }

        fn get_disassembly_of_bytes(
            &self,
            _language: &dyn Language,
            _is_big_endian: bool,
            _address: i64,
            _byte_string: &[u8],
        ) -> Result<String, Box<dyn Error>> {
            Ok("test bytes disassembly".to_string())
        }

        fn is_supported_language(&self, _language: &dyn Language) -> bool {
            self.supported
        }

        fn destroy(&self) {}
    }

    #[test]
    fn test_disassembler_trait_is_object_safe() {
        let disassembler: Box<dyn ExternalDisassembler> = Box::new(TestDisassembler {
            supported: true,
        });
        let language = MockLanguage;
        assert!(disassembler.is_supported_language(&language));
    }

    #[test]
    fn test_get_disassembly_returns_ok() {
        let disassembler = TestDisassembler { supported: true };
        let cu = MockCodeUnit;
        let result = disassembler.get_disassembly(&cu);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test disassembly");
    }

    #[test]
    fn test_get_disassembly_display_prefix_returns_ok() {
        let disassembler = TestDisassembler { supported: true };
        let cu = MockCodeUnit;
        let result = disassembler.get_disassembly_display_prefix(&cu);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test prefix");
    }

    #[test]
    fn test_get_disassembly_of_bytes_returns_ok() {
        let disassembler = TestDisassembler { supported: true };
        let language = MockLanguage;
        let bytes = [0x90u8, 0x00, 0x00, 0x00];
        let result = disassembler.get_disassembly_of_bytes(&language, true, 0x1000, &bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test bytes disassembly");
    }

    #[test]
    fn test_is_supported_language_true() {
        let disassembler = TestDisassembler { supported: true };
        let language = MockLanguage;
        assert!(disassembler.is_supported_language(&language));
    }

    #[test]
    fn test_is_supported_language_false() {
        let disassembler = TestDisassembler { supported: false };
        let language = MockLanguage;
        assert!(!disassembler.is_supported_language(&language));
    }

    #[test]
    fn test_destroy_does_not_panic() {
        let disassembler = TestDisassembler { supported: true };
        disassembler.destroy();
    }
}
