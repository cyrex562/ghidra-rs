/// A single argument of a variadic function, consisting of a length modifier
/// and a conversion specifier from a format string (e.g. `printf`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FormatArgument {
    pub length_modifier: String,
    pub conversion_specifier: String,
}

impl FormatArgument {
    pub fn new(length_modifier: String, conversion_specifier: String) -> Self {
        Self {
            length_modifier,
            conversion_specifier,
        }
    }
}

impl std::fmt::Display for FormatArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]", self.length_modifier, self.conversion_specifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stores_fields() {
        let arg = FormatArgument::new("l".to_string(), "d".to_string());
        assert_eq!(arg.length_modifier, "l");
        assert_eq!(arg.conversion_specifier, "d");
    }

    #[test]
    fn test_display() {
        let arg = FormatArgument::new("ll".to_string(), "u".to_string());
        assert_eq!(arg.to_string(), "[ll, u]");
    }

    #[test]
    fn test_display_empty_modifier() {
        let arg = FormatArgument::new(String::new(), "s".to_string());
        assert_eq!(arg.to_string(), "[, s]");
    }

    #[test]
    fn test_equality() {
        let a = FormatArgument::new("h".to_string(), "i".to_string());
        let b = FormatArgument::new("h".to_string(), "i".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality() {
        let a = FormatArgument::new("h".to_string(), "i".to_string());
        let b = FormatArgument::new("l".to_string(), "i".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn test_clone() {
        let original = FormatArgument::new("L".to_string(), "f".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_debug() {
        let arg = FormatArgument::new("z".to_string(), "x".to_string());
        let s = format!("{:?}", arg);
        assert!(s.contains("FormatArgument"));
        assert!(s.contains("z"));
        assert!(s.contains("x"));
    }
}
