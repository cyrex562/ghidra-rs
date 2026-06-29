/// Listing result tuple used in PDB test utilities: address, symbol, and type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListingResult {
    pub addr: String,
    pub symbol: String,
    pub r#type: String,
}

impl ListingResult {
    pub fn new(
        addr: impl Into<String>,
        symbol: impl Into<String>,
        r#type: impl Into<String>,
    ) -> Self {
        Self {
            addr: addr.into(),
            symbol: symbol.into(),
            r#type: r#type.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fields_stored_correctly() {
        let lr = ListingResult::new("0x1000", "my_symbol", "int");
        assert_eq!(lr.addr, "0x1000");
        assert_eq!(lr.symbol, "my_symbol");
        assert_eq!(lr.r#type, "int");
    }

    #[test]
    fn test_equality() {
        let a = ListingResult::new("0x0", "foo", "void");
        let b = ListingResult::new("0x0", "foo", "void");
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality() {
        let a = ListingResult::new("0x0", "foo", "void");
        let b = ListingResult::new("0x1", "foo", "void");
        assert_ne!(a, b);
    }

    #[test]
    fn test_clone() {
        let a = ListingResult::new("0x10", "sym", "u32");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
