/// Magic bytes identifying an eXtensible ARchive (XAR) file: `xar!`.
pub const MAGIC_BYTES: [u8; 4] = [b'x', b'a', b'r', b'!'];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_value() {
        assert_eq!(MAGIC_BYTES, [0x78, 0x61, 0x72, 0x21]);
    }

    #[test]
    fn magic_bytes_ascii() {
        assert_eq!(&MAGIC_BYTES, b"xar!");
    }
}
