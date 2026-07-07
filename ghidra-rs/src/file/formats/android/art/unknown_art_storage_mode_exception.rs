use std::fmt;

#[derive(Debug)]
pub struct UnknownArtStorageModeException {
    storage_mode: u32,
}

impl UnknownArtStorageModeException {
    pub fn new(storage_mode: u32) -> Self {
        Self { storage_mode }
    }
}

impl fmt::Display for UnknownArtStorageModeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unrecognized storage mode: 0x{:x}", self.storage_mode)
    }
}

impl std::error::Error for UnknownArtStorageModeException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_format() {
        let e = UnknownArtStorageModeException::new(0x07);
        assert_eq!(e.to_string(), "Unrecognized storage mode: 0x7");
    }

    #[test]
    fn message_format_zero() {
        let e = UnknownArtStorageModeException::new(0);
        assert_eq!(e.to_string(), "Unrecognized storage mode: 0x0");
    }

    #[test]
    fn message_format_hex() {
        let e = UnknownArtStorageModeException::new(0xff);
        assert_eq!(e.to_string(), "Unrecognized storage mode: 0xff");
    }

    #[test]
    fn debug_formats() {
        let e = UnknownArtStorageModeException::new(1);
        let s = format!("{:?}", e);
        assert!(s.contains("UnknownArtStorageModeException"));
    }

    #[test]
    fn is_error() {
        let e = UnknownArtStorageModeException::new(2);
        let _: &dyn std::error::Error = &e;
    }
}
