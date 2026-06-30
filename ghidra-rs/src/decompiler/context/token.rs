/// A token in the pcode context, representing a named byte field with endianness.
///
/// Corresponds to `ghidra.pcodeCPort.context.Token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    name: String,
    /// Number of bytes in the token.
    size: i32,
    /// Index of this token, for resolving offsets.
    index: i32,
    bigendian: bool,
}

impl Token {
    pub fn new(name: impl Into<String>, size: i32, bigendian: bool, index: i32) -> Self {
        Self {
            name: name.into(),
            size,
            index,
            bigendian,
        }
    }

    pub fn size(&self) -> i32 {
        self.size
    }

    pub fn is_big_endian(&self) -> bool {
        self.bigendian
    }

    pub fn index(&self) -> i32 {
        self.index
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Token{{{}:{}:{}:{}}}",
            self.name,
            self.size,
            self.index,
            if self.bigendian { "big" } else { "little" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token() -> Token {
        Token::new("tok", 4, true, 2)
    }

    #[test]
    fn accessors() {
        let t = make_token();
        assert_eq!(t.name(), "tok");
        assert_eq!(t.size(), 4);
        assert!(t.is_big_endian());
        assert_eq!(t.index(), 2);
    }

    #[test]
    fn little_endian_token() {
        let t = Token::new("le", 2, false, 0);
        assert!(!t.is_big_endian());
    }

    #[test]
    fn display_big_endian() {
        let t = make_token();
        assert_eq!(t.to_string(), "Token{tok:4:2:big}");
    }

    #[test]
    fn display_little_endian() {
        let t = Token::new("x", 1, false, 0);
        assert_eq!(t.to_string(), "Token{x:1:0:little}");
    }

    #[test]
    fn clone_equality() {
        let t = make_token();
        assert_eq!(t.clone(), t);
    }
}
