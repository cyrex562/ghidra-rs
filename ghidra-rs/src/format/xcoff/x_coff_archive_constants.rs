/// Magic string that identifies an XCOFF big archive file.
pub const MAGIC: &str = "<bigaf>\n";

/// Length of the XCOFF big archive magic string in bytes.
pub const MAGIC_LEN: usize = MAGIC.len();

/// Raw bytes of the XCOFF big archive magic string.
pub const MAGIC_BYTES: &[u8] = MAGIC.as_bytes();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_value() {
        assert_eq!(MAGIC, "<bigaf>\n");
    }

    #[test]
    fn magic_len_matches_magic() {
        assert_eq!(MAGIC_LEN, MAGIC.len());
        assert_eq!(MAGIC_LEN, 8);
    }

    #[test]
    fn magic_bytes_match_magic() {
        assert_eq!(MAGIC_BYTES, MAGIC.as_bytes());
        assert_eq!(MAGIC_BYTES, b"<bigaf>\n");
    }
}
