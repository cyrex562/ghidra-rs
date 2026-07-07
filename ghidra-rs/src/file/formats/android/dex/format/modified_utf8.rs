/// Error type for Modified UTF-8 decoding failures.
///
/// Mirrors the `UTFDataFormatException` and `IOException` thrown by
/// `ghidra.file.formats.android.dex.format.ModifiedUTF8`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModifiedUtf8Error {
    BadSecondByte,
    BadSecondOrThirdByte,
    BadByte,
    InvalidUtf16,
    Io(String),
}

impl std::fmt::Display for ModifiedUtf8Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModifiedUtf8Error::BadSecondByte => write!(f, "bad second byte"),
            ModifiedUtf8Error::BadSecondOrThirdByte => write!(f, "bad second or third byte"),
            ModifiedUtf8Error::BadByte => write!(f, "bad byte"),
            ModifiedUtf8Error::InvalidUtf16 => write!(f, "invalid UTF-16 sequence"),
            ModifiedUtf8Error::Io(msg) => write!(f, "IO error: {msg}"),
        }
    }
}

impl std::error::Error for ModifiedUtf8Error {}

impl From<std::io::Error> for ModifiedUtf8Error {
    fn from(e: std::io::Error) -> Self {
        ModifiedUtf8Error::Io(e.to_string())
    }
}

/// Decoder for the Modified UTF-8 (MUTF-8) encoding used in Android DEX files.
///
/// https://source.android.com/devices/tech/dalvik/dex-format#mutf-8
pub struct ModifiedUtf8;

impl ModifiedUtf8 {
    /// Decodes a null-terminated MUTF-8 byte stream into a `String`.
    ///
    /// Reads bytes from `reader` until a null byte (0x00) is encountered. The `out`
    /// buffer holds UTF-16 code units accumulated during decoding; callers may pass a
    /// pre-allocated `Vec` to amortise allocation across repeated calls. The buffer is
    /// cleared on entry.
    ///
    /// This is a direct port of `ModifiedUTF8.decode(InputStream, char[])`. Java's
    /// `char` is a UTF-16 code unit, so the intermediate buffer is `Vec<u16>`;
    /// surrogate pairs produced by two successive 3-byte sequences are decoded
    /// correctly by `String::from_utf16`.
    pub fn decode(
        reader: &mut impl std::io::Read,
        out: &mut Vec<u16>,
    ) -> Result<String, ModifiedUtf8Error> {
        out.clear();
        let mut buf = [0u8; 1];

        loop {
            reader.read_exact(&mut buf).map_err(ModifiedUtf8Error::from)?;
            let a = buf[0] as u32;

            if a == 0 {
                return String::from_utf16(out).map_err(|_| ModifiedUtf8Error::InvalidUtf16);
            }

            if a < 0x80 {
                out.push(a as u16);
            } else if (a & 0xE0) == 0xC0 {
                reader.read_exact(&mut buf).map_err(ModifiedUtf8Error::from)?;
                let b = buf[0] as u32;
                if (b & 0xC0) != 0x80 {
                    return Err(ModifiedUtf8Error::BadSecondByte);
                }
                out.push((((a & 0x1F) << 6) | (b & 0x3F)) as u16);
            } else if (a & 0xF0) == 0xE0 {
                reader.read_exact(&mut buf).map_err(ModifiedUtf8Error::from)?;
                let b = buf[0] as u32;
                reader.read_exact(&mut buf).map_err(ModifiedUtf8Error::from)?;
                let c = buf[0] as u32;
                if ((b & 0xC0) != 0x80) || ((c & 0xC0) != 0x80) {
                    return Err(ModifiedUtf8Error::BadSecondOrThirdByte);
                }
                out.push((((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F)) as u16);
            } else {
                return Err(ModifiedUtf8Error::BadByte);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn decode(bytes: &[u8]) -> Result<String, ModifiedUtf8Error> {
        let mut reader = Cursor::new(bytes);
        let mut out = Vec::new();
        ModifiedUtf8::decode(&mut reader, &mut out)
    }

    #[test]
    fn ascii_string() {
        let mut bytes = b"hello".to_vec();
        bytes.push(0);
        assert_eq!(decode(&bytes).unwrap(), "hello");
    }

    #[test]
    fn empty_string() {
        assert_eq!(decode(&[0]).unwrap(), "");
    }

    #[test]
    fn two_byte_sequence() {
        // U+00C9 'É' in MUTF-8: 0xC3 0x89
        let bytes = [0xC3, 0x89, 0x00];
        assert_eq!(decode(&bytes).unwrap(), "É");
    }

    #[test]
    fn three_byte_sequence() {
        // U+4E2D '中' in MUTF-8: 0xE4 0xB8 0xAD
        let bytes = [0xE4, 0xB8, 0xAD, 0x00];
        assert_eq!(decode(&bytes).unwrap(), "中");
    }

    #[test]
    fn mixed_sequence() {
        // "A中B" => 0x41, 0xE4 0xB8 0xAD, 0x42, 0x00
        let bytes = [0x41, 0xE4, 0xB8, 0xAD, 0x42, 0x00];
        assert_eq!(decode(&bytes).unwrap(), "A中B");
    }

    #[test]
    fn mutf8_null_char_encoding() {
        // MUTF-8 encodes U+0000 as 0xC0 0x80, not as a literal 0x00
        let bytes = [0xC0, 0x80, 0x41, 0x00];
        let result = decode(&bytes).unwrap();
        assert_eq!(result.chars().count(), 2);
        let mut chars = result.chars();
        assert_eq!(chars.next(), Some('\u{0000}'));
        assert_eq!(chars.next(), Some('A'));
    }

    #[test]
    fn error_bad_second_byte_two_byte() {
        // First byte starts 2-byte sequence; second byte has wrong continuation bits
        let bytes = [0xC3, 0x41, 0x00];
        assert_eq!(decode(&bytes).unwrap_err(), ModifiedUtf8Error::BadSecondByte);
    }

    #[test]
    fn error_bad_second_byte_three_byte() {
        // First byte starts 3-byte sequence; second byte is bad
        let bytes = [0xE4, 0x41, 0x80, 0x00];
        assert_eq!(
            decode(&bytes).unwrap_err(),
            ModifiedUtf8Error::BadSecondOrThirdByte
        );
    }

    #[test]
    fn error_bad_third_byte_three_byte() {
        // First and second bytes are valid; third byte has wrong continuation bits
        let bytes = [0xE4, 0xB8, 0x41, 0x00];
        assert_eq!(
            decode(&bytes).unwrap_err(),
            ModifiedUtf8Error::BadSecondOrThirdByte
        );
    }

    #[test]
    fn error_bad_first_byte() {
        // 0xF0 starts a 4-byte sequence which MUTF-8 does not support
        let bytes = [0xF0, 0x90, 0x80, 0x80, 0x00];
        assert_eq!(decode(&bytes).unwrap_err(), ModifiedUtf8Error::BadByte);
    }

    #[test]
    fn reuses_out_buffer() {
        let mut out: Vec<u16> = Vec::with_capacity(32);
        let mut reader = Cursor::new(b"hi\0");
        let s = ModifiedUtf8::decode(&mut reader, &mut out).unwrap();
        assert_eq!(s, "hi");
        // second call reuses the same buffer
        let mut reader2 = Cursor::new(b"bye\0");
        let s2 = ModifiedUtf8::decode(&mut reader2, &mut out).unwrap();
        assert_eq!(s2, "bye");
    }
}
