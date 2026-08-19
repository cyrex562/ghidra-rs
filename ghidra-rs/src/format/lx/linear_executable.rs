use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// A class to manage loading Linear Executables (LX).
///
/// This mirrors `ghidra.app.util.bin.format.lx.LinearExecutable`.
pub struct LinearExecutable {
    _private: (),
}

impl LinearExecutable {
    /// The magic number for LX executables.
    pub const IMAGE_LX_SIGNATURE: u16 = 0x584c; // LX

    /// Creates a new LinearExecutable from the given byte provider.
    ///
    /// This returns an error as LX format parsing is not yet implemented.
    pub fn new(_bp: &mut dyn ByteProvider) -> Result<Self, &'static str> {
        Err("LinearExecutable is not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_lx_signature_is_correct() {
        assert_eq!(LinearExecutable::IMAGE_LX_SIGNATURE, 0x584c);
    }

    #[test]
    fn image_lx_signature_represents_lx() {
        let bytes = LinearExecutable::IMAGE_LX_SIGNATURE.to_le_bytes();
        assert_eq!(bytes, [0x4c, 0x58]); // 'L', 'X'
    }

    #[test]
    fn constructor_returns_not_yet_implemented_error() {
        struct MockByteProvider;
        impl ByteProvider for MockByteProvider {
            fn length(&mut self) -> std::io::Result<u64> {
                Ok(0)
            }
            fn is_valid_index(&mut self, _index: u64) -> bool {
                false
            }
            fn read_byte(&mut self, _index: u64) -> std::io::Result<u8> {
                Ok(0)
            }
            fn read_bytes(&mut self, _index: u64, _length: usize) -> std::io::Result<Vec<u8>> {
                Ok(vec![])
            }
            fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
                Ok(())
            }
            fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut provider = MockByteProvider;
        let result = LinearExecutable::new(&mut provider);
        assert!(result.is_err());
        assert_eq!(result.err(), Some("LinearExecutable is not yet implemented"));
    }
}
