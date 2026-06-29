/// Binary property list format constants.
///
/// Corresponds to `ghidra.file.formats.bplist.BinaryPropertyListConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BinaryPropertyListConstants;

impl BinaryPropertyListConstants {
    pub const BINARY_PLIST_MAGIC: &'static str = "bplist";
    pub const TRAILER_SIZE: u32 = 32;
    /// ASCII value of `'0'` (0x30 / 48), marking the major version 0 byte.
    pub const MAJOR_VERSION_0: u8 = b'0';
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_value() {
        assert_eq!(BinaryPropertyListConstants::BINARY_PLIST_MAGIC, "bplist");
    }

    #[test]
    fn trailer_size_value() {
        assert_eq!(BinaryPropertyListConstants::TRAILER_SIZE, 32);
    }

    #[test]
    fn major_version_0_is_ascii_zero() {
        assert_eq!(BinaryPropertyListConstants::MAJOR_VERSION_0, b'0');
        assert_eq!(BinaryPropertyListConstants::MAJOR_VERSION_0, 0x30);
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(BinaryPropertyListConstants::default(), BinaryPropertyListConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = BinaryPropertyListConstants;
        assert_eq!(a, a.clone());
    }
}
