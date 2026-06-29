/// Address, name, and bytes tuple used in PDB test utilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressNameBytes {
    pub addr: String,
    pub name: String,
    pub bytes: String,
}

impl AddressNameBytes {
    pub fn new(addr: impl Into<String>, name: impl Into<String>, bytes: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            name: name.into(),
            bytes: bytes.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fields_stored_correctly() {
        let anb = AddressNameBytes::new("0x1000", "foo", "DE AD BE EF");
        assert_eq!(anb.addr, "0x1000");
        assert_eq!(anb.name, "foo");
        assert_eq!(anb.bytes, "DE AD BE EF");
    }

    #[test]
    fn test_equality() {
        let a = AddressNameBytes::new("0x0", "bar", "FF");
        let b = AddressNameBytes::new("0x0", "bar", "FF");
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality() {
        let a = AddressNameBytes::new("0x0", "bar", "FF");
        let b = AddressNameBytes::new("0x1", "bar", "FF");
        assert_ne!(a, b);
    }

    #[test]
    fn test_clone() {
        let a = AddressNameBytes::new("0x10", "sym", "00");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
