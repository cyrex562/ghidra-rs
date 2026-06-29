/// Verifier error bit-flag constants, mirroring
/// `ghidra.file.formats.android.verifier.VerifyError`.
///
/// Source:
/// <https://android.googlesource.com/platform/art/+/master/runtime/verifier/verifier_enums.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyError;

impl VerifyError {
    pub const VERIFY_ERROR_BAD_CLASS_HARD: u32 = 1 << 0;
    pub const VERIFY_ERROR_BAD_CLASS_SOFT: u32 = 1 << 1;
    pub const VERIFY_ERROR_NO_CLASS: u32 = 1 << 2;
    pub const VERIFY_ERROR_NO_FIELD: u32 = 1 << 3;
    pub const VERIFY_ERROR_NO_METHOD: u32 = 1 << 4;
    pub const VERIFY_ERROR_ACCESS_CLASS: u32 = 1 << 5;
    pub const VERIFY_ERROR_ACCESS_FIELD: u32 = 1 << 6;
    pub const VERIFY_ERROR_ACCESS_METHOD: u32 = 1 << 7;
    pub const VERIFY_ERROR_CLASS_CHANGE: u32 = 1 << 8;
    pub const VERIFY_ERROR_INSTANTIATION: u32 = 1 << 9;
    pub const VERIFY_ERROR_FORCE_INTERPRETER: u32 = 1 << 10;
    pub const VERIFY_ERROR_LOCKING: u32 = 1 << 11;
    pub const VERIFY_ERROR_SKIP_COMPILER: u32 = 1 << 31;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_powers_of_two() {
        let flags = [
            VerifyError::VERIFY_ERROR_BAD_CLASS_HARD,
            VerifyError::VERIFY_ERROR_BAD_CLASS_SOFT,
            VerifyError::VERIFY_ERROR_NO_CLASS,
            VerifyError::VERIFY_ERROR_NO_FIELD,
            VerifyError::VERIFY_ERROR_NO_METHOD,
            VerifyError::VERIFY_ERROR_ACCESS_CLASS,
            VerifyError::VERIFY_ERROR_ACCESS_FIELD,
            VerifyError::VERIFY_ERROR_ACCESS_METHOD,
            VerifyError::VERIFY_ERROR_CLASS_CHANGE,
            VerifyError::VERIFY_ERROR_INSTANTIATION,
            VerifyError::VERIFY_ERROR_FORCE_INTERPRETER,
            VerifyError::VERIFY_ERROR_LOCKING,
            VerifyError::VERIFY_ERROR_SKIP_COMPILER,
        ];
        for f in flags {
            assert!(f.is_power_of_two(), "{f} is not a power of two");
        }
    }

    #[test]
    fn constants_are_distinct() {
        let flags = [
            VerifyError::VERIFY_ERROR_BAD_CLASS_HARD,
            VerifyError::VERIFY_ERROR_BAD_CLASS_SOFT,
            VerifyError::VERIFY_ERROR_NO_CLASS,
            VerifyError::VERIFY_ERROR_NO_FIELD,
            VerifyError::VERIFY_ERROR_NO_METHOD,
            VerifyError::VERIFY_ERROR_ACCESS_CLASS,
            VerifyError::VERIFY_ERROR_ACCESS_FIELD,
            VerifyError::VERIFY_ERROR_ACCESS_METHOD,
            VerifyError::VERIFY_ERROR_CLASS_CHANGE,
            VerifyError::VERIFY_ERROR_INSTANTIATION,
            VerifyError::VERIFY_ERROR_FORCE_INTERPRETER,
            VerifyError::VERIFY_ERROR_LOCKING,
            VerifyError::VERIFY_ERROR_SKIP_COMPILER,
        ];
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_ne!(flags[i], flags[j]);
            }
        }
    }

    #[test]
    fn constants_do_not_overlap() {
        let flags = [
            VerifyError::VERIFY_ERROR_BAD_CLASS_HARD,
            VerifyError::VERIFY_ERROR_BAD_CLASS_SOFT,
            VerifyError::VERIFY_ERROR_NO_CLASS,
            VerifyError::VERIFY_ERROR_NO_FIELD,
            VerifyError::VERIFY_ERROR_NO_METHOD,
            VerifyError::VERIFY_ERROR_ACCESS_CLASS,
            VerifyError::VERIFY_ERROR_ACCESS_FIELD,
            VerifyError::VERIFY_ERROR_ACCESS_METHOD,
            VerifyError::VERIFY_ERROR_CLASS_CHANGE,
            VerifyError::VERIFY_ERROR_INSTANTIATION,
            VerifyError::VERIFY_ERROR_FORCE_INTERPRETER,
            VerifyError::VERIFY_ERROR_LOCKING,
            VerifyError::VERIFY_ERROR_SKIP_COMPILER,
        ];
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_eq!(flags[i] & flags[j], 0);
            }
        }
    }

    #[test]
    fn explicit_bit_positions() {
        assert_eq!(VerifyError::VERIFY_ERROR_BAD_CLASS_HARD, 0x0001);
        assert_eq!(VerifyError::VERIFY_ERROR_BAD_CLASS_SOFT, 0x0002);
        assert_eq!(VerifyError::VERIFY_ERROR_NO_CLASS, 0x0004);
        assert_eq!(VerifyError::VERIFY_ERROR_NO_FIELD, 0x0008);
        assert_eq!(VerifyError::VERIFY_ERROR_NO_METHOD, 0x0010);
        assert_eq!(VerifyError::VERIFY_ERROR_ACCESS_CLASS, 0x0020);
        assert_eq!(VerifyError::VERIFY_ERROR_ACCESS_FIELD, 0x0040);
        assert_eq!(VerifyError::VERIFY_ERROR_ACCESS_METHOD, 0x0080);
        assert_eq!(VerifyError::VERIFY_ERROR_CLASS_CHANGE, 0x0100);
        assert_eq!(VerifyError::VERIFY_ERROR_INSTANTIATION, 0x0200);
        assert_eq!(VerifyError::VERIFY_ERROR_FORCE_INTERPRETER, 0x0400);
        assert_eq!(VerifyError::VERIFY_ERROR_LOCKING, 0x0800);
        assert_eq!(VerifyError::VERIFY_ERROR_SKIP_COMPILER, 0x8000_0000);
    }

    #[test]
    fn flags_can_be_combined() {
        let combined = VerifyError::VERIFY_ERROR_BAD_CLASS_HARD
            | VerifyError::VERIFY_ERROR_NO_CLASS
            | VerifyError::VERIFY_ERROR_SKIP_COMPILER;
        assert_eq!(combined & VerifyError::VERIFY_ERROR_BAD_CLASS_HARD, VerifyError::VERIFY_ERROR_BAD_CLASS_HARD);
        assert_eq!(combined & VerifyError::VERIFY_ERROR_NO_CLASS, VerifyError::VERIFY_ERROR_NO_CLASS);
        assert_eq!(combined & VerifyError::VERIFY_ERROR_SKIP_COMPILER, VerifyError::VERIFY_ERROR_SKIP_COMPILER);
        assert_eq!(combined & VerifyError::VERIFY_ERROR_NO_FIELD, 0);
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(VerifyError::default(), VerifyError);
    }

    #[test]
    fn clone_is_equal() {
        let v = VerifyError;
        assert_eq!(v, v.clone());
    }
}
