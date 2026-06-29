/// Number type variants for binary property list NSNumber objects.
///
/// Corresponds to `ghidra.file.formats.bplist.NSNumberTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsNumberTypes {
    Byte,
    Short,
    Integer,
    Long,
    Real,
    Boolean,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_distinct() {
        let variants = [
            NsNumberTypes::Byte,
            NsNumberTypes::Short,
            NsNumberTypes::Integer,
            NsNumberTypes::Long,
            NsNumberTypes::Real,
            NsNumberTypes::Boolean,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let v = NsNumberTypes::Integer;
        let cloned = v.clone();
        let copied = v;
        assert_eq!(v, cloned);
        assert_eq!(v, copied);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", NsNumberTypes::Byte), "Byte");
        assert_eq!(format!("{:?}", NsNumberTypes::Short), "Short");
        assert_eq!(format!("{:?}", NsNumberTypes::Integer), "Integer");
        assert_eq!(format!("{:?}", NsNumberTypes::Long), "Long");
        assert_eq!(format!("{:?}", NsNumberTypes::Real), "Real");
        assert_eq!(format!("{:?}", NsNumberTypes::Boolean), "Boolean");
    }
}
