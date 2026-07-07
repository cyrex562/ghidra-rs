use crate::program::model::address::Address;

/// A repeatable comment reached via a reference, paired with the address it applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RefRepeatComment {
    address: Address,
    comment_lines: Vec<String>,
}

impl RefRepeatComment {
    pub fn new(address: Address, comment_lines: Vec<String>) -> Self {
        RefRepeatComment {
            address,
            comment_lines,
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn comment_lines(&self) -> &[String] {
        &self.comment_lines
    }

    pub fn comment_line_count(&self) -> usize {
        self.comment_lines.len()
    }
}

impl std::fmt::Display for RefRepeatComment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", self.comment_lines.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn test_accessors() {
        let comment = RefRepeatComment::new(
            addr(0x100),
            vec!["line one".to_string(), "line two".to_string()],
        );
        assert_eq!(comment.address(), &addr(0x100));
        assert_eq!(comment.comment_lines(), &["line one", "line two"]);
        assert_eq!(comment.comment_line_count(), 2);
    }

    #[test]
    fn test_equality() {
        let a = RefRepeatComment::new(addr(0x100), vec!["hello".to_string()]);
        let b = RefRepeatComment::new(addr(0x100), vec!["hello".to_string()]);
        let c = RefRepeatComment::new(addr(0x200), vec!["hello".to_string()]);
        let d = RefRepeatComment::new(addr(0x100), vec!["world".to_string()]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn test_display() {
        let comment =
            RefRepeatComment::new(addr(0x0), vec!["foo".to_string(), "bar".to_string()]);
        assert_eq!(comment.to_string(), "[foo, bar]");
    }

    #[test]
    fn test_empty_comment_lines() {
        let comment = RefRepeatComment::new(addr(0x0), vec![]);
        assert_eq!(comment.comment_line_count(), 0);
        assert_eq!(comment.to_string(), "[]");
    }
}
