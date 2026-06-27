/// Enumeration of file types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    File,
    Directory,
    SymbolicLink,
    Other,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::FileType;

    #[test]
    fn variants_are_distinct() {
        let variants = [
            FileType::File,
            FileType::Directory,
            FileType::SymbolicLink,
            FileType::Other,
            FileType::Unknown,
        ];
        for (i, &a) in variants.iter().enumerate() {
            for &b in variants[..i].iter() {
                assert_ne!(a, b, "enum variants must be distinct");
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let ft = FileType::File;
        let ft2 = ft;
        assert_eq!(ft, ft2);
        let ft3 = ft.clone();
        assert_eq!(ft, ft3);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", FileType::File), "File");
        assert_eq!(format!("{:?}", FileType::Directory), "Directory");
        assert_eq!(format!("{:?}", FileType::SymbolicLink), "SymbolicLink");
        assert_eq!(format!("{:?}", FileType::Other), "Other");
        assert_eq!(format!("{:?}", FileType::Unknown), "Unknown");
    }
}
