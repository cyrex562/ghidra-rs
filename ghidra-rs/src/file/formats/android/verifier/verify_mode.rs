/// Verification mode for ART, mirroring
/// `ghidra.file.formats.android.verifier.VerifyMode`.
///
/// Source:
/// <https://android.googlesource.com/platform/art/+/master/runtime/verifier/verifier_enums.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    KNone,
    KEnable,
    KSoftFail,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(VerifyMode::KNone, VerifyMode::KEnable);
        assert_ne!(VerifyMode::KEnable, VerifyMode::KSoftFail);
        assert_ne!(VerifyMode::KNone, VerifyMode::KSoftFail);
    }

    #[test]
    fn variants_are_copy() {
        let m = VerifyMode::KEnable;
        let _m2 = m;
        let _m3 = m;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", VerifyMode::KNone), "KNone");
        assert_eq!(format!("{:?}", VerifyMode::KEnable), "KEnable");
        assert_eq!(format!("{:?}", VerifyMode::KSoftFail), "KSoftFail");
    }

    #[test]
    fn variants_clone() {
        let m = VerifyMode::KSoftFail;
        assert_eq!(m.clone(), VerifyMode::KSoftFail);
    }
}
