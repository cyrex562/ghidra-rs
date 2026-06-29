/// YAFFS2 object type.
///
/// Discriminant values match the yaffs enum ordinals used in the on-disk format.
/// Mirrors `ghidra.file.formats.yaffs2.YAFFS2ObjectType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Yaffs2ObjectType {
    Unknown = 0,
    File = 1,
    Symlink = 2,
    Directory = 3,
    Hardlink = 4,
    Special = 5,
    /// Sentinel returned for any value that does not map to a known type,
    /// including `Unknown` (0).
    Invalid = 6,
}

impl Yaffs2ObjectType {
    /// Parse a raw integer into a [`Yaffs2ObjectType`].
    ///
    /// Only values strictly greater than `Unknown` (0) and strictly less than
    /// `Invalid` (6) are considered valid; everything else returns
    /// [`Yaffs2ObjectType::Invalid`].  This mirrors the Java `parse(long)`
    /// method whose comment states that `INVALID` represents "value that
    /// doesn't match, including Unknown".
    pub fn parse(i: i64) -> Self {
        match i {
            1 => Self::File,
            2 => Self::Symlink,
            3 => Self::Directory,
            4 => Self::Hardlink,
            5 => Self::Special,
            _ => Self::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_values() {
        assert_eq!(Yaffs2ObjectType::parse(1), Yaffs2ObjectType::File);
        assert_eq!(Yaffs2ObjectType::parse(2), Yaffs2ObjectType::Symlink);
        assert_eq!(Yaffs2ObjectType::parse(3), Yaffs2ObjectType::Directory);
        assert_eq!(Yaffs2ObjectType::parse(4), Yaffs2ObjectType::Hardlink);
        assert_eq!(Yaffs2ObjectType::parse(5), Yaffs2ObjectType::Special);
    }

    #[test]
    fn parse_unknown_returns_invalid() {
        assert_eq!(Yaffs2ObjectType::parse(0), Yaffs2ObjectType::Invalid);
    }

    #[test]
    fn parse_out_of_range_returns_invalid() {
        assert_eq!(Yaffs2ObjectType::parse(6), Yaffs2ObjectType::Invalid);
        assert_eq!(Yaffs2ObjectType::parse(7), Yaffs2ObjectType::Invalid);
        assert_eq!(Yaffs2ObjectType::parse(-1), Yaffs2ObjectType::Invalid);
        assert_eq!(Yaffs2ObjectType::parse(100), Yaffs2ObjectType::Invalid);
    }

    #[test]
    fn discriminants_match_yaffs_ordinals() {
        assert_eq!(Yaffs2ObjectType::Unknown as i64, 0);
        assert_eq!(Yaffs2ObjectType::File as i64, 1);
        assert_eq!(Yaffs2ObjectType::Symlink as i64, 2);
        assert_eq!(Yaffs2ObjectType::Directory as i64, 3);
        assert_eq!(Yaffs2ObjectType::Hardlink as i64, 4);
        assert_eq!(Yaffs2ObjectType::Special as i64, 5);
        assert_eq!(Yaffs2ObjectType::Invalid as i64, 6);
    }

    #[test]
    fn variants_are_copy() {
        let v = Yaffs2ObjectType::File;
        let _v2 = v;
        let _v3 = v;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", Yaffs2ObjectType::Invalid), "Invalid");
        assert_eq!(format!("{:?}", Yaffs2ObjectType::Directory), "Directory");
    }
}
