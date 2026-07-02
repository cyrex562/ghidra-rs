/// Resource type ID for the Code Fragment Manager (CFM): `'cfrg'`.
pub const TYPE_CFRG: u32 = 0x63667267;

/// Resource type ID for `'str '` (Pascal string).
pub const TYPE_STR_SPACE: u32 = 0x53545220;

/// Resource type ID for `'str#'` (Pascal string list).
pub const TYPE_STR_POUND: u32 = 0x53545223;

/// Resource type ID for `'ICN#'` (icon list).
pub const TYPE_ICON: u32 = 0x49434E23;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fourcc_values_match_java_source() {
        assert_eq!(TYPE_CFRG, 0x63667267);
        assert_eq!(TYPE_STR_SPACE, 0x53545220);
        assert_eq!(TYPE_STR_POUND, 0x53545223);
        assert_eq!(TYPE_ICON, 0x49434E23);
    }

    #[test]
    fn fourcc_bytes_match_ascii() {
        assert_eq!(&TYPE_CFRG.to_be_bytes(), b"cfrg");
        assert_eq!(&TYPE_STR_SPACE.to_be_bytes(), b"STR ");
        assert_eq!(&TYPE_STR_POUND.to_be_bytes(), b"STR#");
        assert_eq!(&TYPE_ICON.to_be_bytes(), b"ICN#");
    }

    #[test]
    fn all_constants_are_distinct() {
        let all = [TYPE_CFRG, TYPE_STR_SPACE, TYPE_STR_POUND, TYPE_ICON];
        for i in 0..all.len() {
            for j in 0..all.len() {
                if i == j {
                    assert_eq!(all[i], all[j]);
                } else {
                    assert_ne!(all[i], all[j]);
                }
            }
        }
    }
}
