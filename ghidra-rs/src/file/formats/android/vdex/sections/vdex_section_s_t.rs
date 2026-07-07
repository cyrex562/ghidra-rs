/// VDEX section identifiers for Android 12 (S) and Android 13 (T).
///
/// Mirrors `ghidra.file.formats.android.vdex.sections.VdexSection_S_T`.
///
/// Reference:
/// - <https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/vdex_file.h#80>
/// - <https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/vdex_file.h#80>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdexSectionST {
    ChecksumSection = 0,
    DexFileSection = 1,
    VerifierDepsSection = 2,
    TypeLookupTableSection = 3,
    NumberOfSections = 4,
}

impl VdexSectionST {
    /// Returns the variant for the given ordinal, or `None` if out of range.
    pub fn from_int(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ChecksumSection),
            1 => Some(Self::DexFileSection),
            2 => Some(Self::VerifierDepsSection),
            3 => Some(Self::TypeLookupTableSection),
            4 => Some(Self::NumberOfSections),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminant_values() {
        assert_eq!(VdexSectionST::ChecksumSection as i32, 0);
        assert_eq!(VdexSectionST::DexFileSection as i32, 1);
        assert_eq!(VdexSectionST::VerifierDepsSection as i32, 2);
        assert_eq!(VdexSectionST::TypeLookupTableSection as i32, 3);
        assert_eq!(VdexSectionST::NumberOfSections as i32, 4);
    }

    #[test]
    fn from_int_valid() {
        assert_eq!(VdexSectionST::from_int(0), Some(VdexSectionST::ChecksumSection));
        assert_eq!(VdexSectionST::from_int(1), Some(VdexSectionST::DexFileSection));
        assert_eq!(VdexSectionST::from_int(2), Some(VdexSectionST::VerifierDepsSection));
        assert_eq!(VdexSectionST::from_int(3), Some(VdexSectionST::TypeLookupTableSection));
        assert_eq!(VdexSectionST::from_int(4), Some(VdexSectionST::NumberOfSections));
    }

    #[test]
    fn from_int_out_of_range() {
        assert_eq!(VdexSectionST::from_int(5), None);
        assert_eq!(VdexSectionST::from_int(-1), None);
        assert_eq!(VdexSectionST::from_int(100), None);
    }

    #[test]
    fn variants_are_copy() {
        let v = VdexSectionST::DexFileSection;
        let _v2 = v;
        let _v3 = v;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", VdexSectionST::ChecksumSection), "ChecksumSection");
        assert_eq!(format!("{:?}", VdexSectionST::NumberOfSections), "NumberOfSections");
    }
}
