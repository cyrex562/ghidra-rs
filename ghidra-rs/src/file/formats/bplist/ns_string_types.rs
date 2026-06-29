/// String encoding type variants for binary property list NSString objects.
///
/// Corresponds to `ghidra.file.formats.bplist.NSStringTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsStringTypes {
    TypeAscii,
    TypeUtf16Be,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_distinct() {
        let variants = [NsStringTypes::TypeAscii, NsStringTypes::TypeUtf16Be];
        assert_ne!(variants[0], variants[1]);
    }

    #[test]
    fn clone_and_copy() {
        let v = NsStringTypes::TypeAscii;
        let cloned = v.clone();
        let copied = v;
        assert_eq!(v, cloned);
        assert_eq!(v, copied);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", NsStringTypes::TypeAscii), "TypeAscii");
        assert_eq!(format!("{:?}", NsStringTypes::TypeUtf16Be), "TypeUtf16Be");
    }
}
