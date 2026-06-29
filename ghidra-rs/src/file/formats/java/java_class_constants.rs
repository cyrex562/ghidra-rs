/// Constants for Java class files.
///
/// Mirrors `ghidra.file.formats.java.JavaClassConstants`.

/// Magic bytes that identify a Java class file (`0xCAFEBABE`).
pub const MAGIC_BYTES: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_match_java_source() {
        assert_eq!(MAGIC_BYTES, [0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn magic_bytes_spell_cafebabe() {
        assert_eq!(MAGIC_BYTES, *b"\xca\xfe\xba\xbe");
    }

    #[test]
    fn magic_bytes_length_is_four() {
        assert_eq!(MAGIC_BYTES.len(), 4);
    }
}
