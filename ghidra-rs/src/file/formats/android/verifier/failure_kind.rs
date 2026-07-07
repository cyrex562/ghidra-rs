/// Verification failure severity, mirroring
/// `ghidra.file.formats.android.verifier.FailureKind`.
///
/// Source:
/// <https://android.googlesource.com/platform/art/+/master/runtime/verifier/verifier_enums.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    NoFailure,
    SoftFailure,
    HardFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(FailureKind::NoFailure, FailureKind::SoftFailure);
        assert_ne!(FailureKind::SoftFailure, FailureKind::HardFailure);
        assert_ne!(FailureKind::NoFailure, FailureKind::HardFailure);
    }

    #[test]
    fn variants_are_copy() {
        let k = FailureKind::HardFailure;
        let _k2 = k;
        let _k3 = k;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", FailureKind::NoFailure), "NoFailure");
        assert_eq!(format!("{:?}", FailureKind::SoftFailure), "SoftFailure");
        assert_eq!(format!("{:?}", FailureKind::HardFailure), "HardFailure");
    }

    #[test]
    fn variants_clone() {
        let k = FailureKind::SoftFailure;
        assert_eq!(k.clone(), FailureKind::SoftFailure);
    }
}
