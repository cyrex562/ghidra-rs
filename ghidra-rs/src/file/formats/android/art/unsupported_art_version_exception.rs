use std::fmt;

#[derive(Debug)]
pub struct UnsupportedArtVersionException {
    magic: String,
    version: String,
}

impl UnsupportedArtVersionException {
    pub fn new(magic: &str, version: &str) -> Self {
        Self {
            magic: magic.trim().to_string(),
            version: version.to_string(),
        }
    }
}

impl fmt::Display for UnsupportedArtVersionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unsupported ART ({}) for version: {}", self.magic, self.version)
    }
}

impl std::error::Error for UnsupportedArtVersionException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_format() {
        let e = UnsupportedArtVersionException::new("art\n", "056");
        assert_eq!(e.to_string(), "Unsupported ART (art) for version: 056");
    }

    #[test]
    fn magic_trimmed() {
        let e = UnsupportedArtVersionException::new("  art  ", "009");
        assert_eq!(e.to_string(), "Unsupported ART (art) for version: 009");
    }

    #[test]
    fn no_trim_needed() {
        let e = UnsupportedArtVersionException::new("art", "056");
        assert_eq!(e.to_string(), "Unsupported ART (art) for version: 056");
    }

    #[test]
    fn debug_formats() {
        let e = UnsupportedArtVersionException::new("art", "056");
        let s = format!("{:?}", e);
        assert!(s.contains("UnsupportedArtVersionException"));
    }

    #[test]
    fn is_error() {
        let e = UnsupportedArtVersionException::new("art", "056");
        let _: &dyn std::error::Error = &e;
    }
}
