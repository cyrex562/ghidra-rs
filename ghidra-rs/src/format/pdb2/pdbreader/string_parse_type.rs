/// Encoding/length-prefix style for a PDB string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringParseType {
    StringSt,
    StringNt,
    StringUtf8St,
    StringUtf8Nt,
    StringWcharNt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(StringParseType::StringSt, StringParseType::StringNt);
        assert_ne!(StringParseType::StringUtf8St, StringParseType::StringUtf8Nt);
        assert_ne!(StringParseType::StringUtf8Nt, StringParseType::StringWcharNt);
    }

    #[test]
    fn copy_and_clone() {
        let a = StringParseType::StringUtf8St;
        let b = a;
        assert_eq!(a, b);
        let c = StringParseType::StringWcharNt.clone();
        assert_eq!(c, StringParseType::StringWcharNt);
    }

    #[test]
    fn debug_output() {
        assert_eq!(format!("{:?}", StringParseType::StringSt), "StringSt");
        assert_eq!(format!("{:?}", StringParseType::StringNt), "StringNt");
        assert_eq!(format!("{:?}", StringParseType::StringUtf8St), "StringUtf8St");
        assert_eq!(format!("{:?}", StringParseType::StringUtf8Nt), "StringUtf8Nt");
        assert_eq!(format!("{:?}", StringParseType::StringWcharNt), "StringWcharNt");
    }

    #[test]
    fn all_variants_covered() {
        let variants = [
            StringParseType::StringSt,
            StringParseType::StringNt,
            StringParseType::StringUtf8St,
            StringParseType::StringUtf8Nt,
            StringParseType::StringWcharNt,
        ];
        assert_eq!(variants.len(), 5);
    }
}
