/// Address, name, and section length tuple used in PDB test utilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressNameLength {
    pub addr: String,
    pub name: String,
    pub length: i32,
}

impl AddressNameLength {
    pub fn new(addr: impl Into<String>, name: impl Into<String>, length: i32) -> Self {
        Self {
            addr: addr.into(),
            name: name.into(),
            length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fields_stored_correctly() {
        let anl = AddressNameLength::new("0x1000", "foo", 64);
        assert_eq!(anl.addr, "0x1000");
        assert_eq!(anl.name, "foo");
        assert_eq!(anl.length, 64);
    }

    #[test]
    fn test_equality() {
        let a = AddressNameLength::new("0x0", "bar", 128);
        let b = AddressNameLength::new("0x0", "bar", 128);
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality_addr() {
        let a = AddressNameLength::new("0x0", "bar", 128);
        let b = AddressNameLength::new("0x1", "bar", 128);
        assert_ne!(a, b);
    }

    #[test]
    fn test_inequality_length() {
        let a = AddressNameLength::new("0x0", "bar", 128);
        let b = AddressNameLength::new("0x0", "bar", 256);
        assert_ne!(a, b);
    }

    #[test]
    fn test_clone() {
        let a = AddressNameLength::new("0x10", "sym", 32);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
