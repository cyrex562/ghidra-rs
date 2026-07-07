use std::fmt;

use crate::program::model::address::Address;

/// Cheap container for match info.
#[derive(Debug, Clone)]
pub struct SubroutineMatch {
    prog_a_addrs: Vec<Address>,
    prog_b_addrs: Vec<Address>,
    reason: String,
}

impl SubroutineMatch {
    pub fn new(reason: impl Into<String>) -> Self {
        SubroutineMatch {
            prog_a_addrs: Vec::new(),
            prog_b_addrs: Vec::new(),
            reason: reason.into(),
        }
    }

    pub fn add(&mut self, addr: Address, is_a: bool) -> bool {
        if is_a {
            self.prog_a_addrs.push(addr);
        } else {
            self.prog_b_addrs.push(addr);
        }
        true
    }

    pub fn remove(&mut self, addr: Option<Address>, is_a: bool) -> bool {
        let Some(addr) = addr else {
            return false;
        };
        if is_a {
            self.prog_a_addrs.retain(|a| *a != addr);
        } else {
            self.prog_b_addrs.retain(|a| *a != addr);
        }
        false
    }

    pub fn get_reason(&self) -> &str {
        &self.reason
    }

    pub fn get_a_addresses(&self) -> &[Address] {
        &self.prog_a_addrs
    }

    pub fn get_b_addresses(&self) -> &[Address] {
        &self.prog_b_addrs
    }

    fn is_one_to_one(&self) -> bool {
        self.prog_a_addrs.len() == 1 && self.prog_b_addrs.len() == 1
    }
}

impl fmt::Display for SubroutineMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.reason)?;
        for addr in &self.prog_a_addrs {
            write!(f, "{},", addr)?;
        }
        write!(f, " --- ")?;
        for addr in &self.prog_b_addrs {
            write!(f, "{},", addr)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn test_new() {
        let m = SubroutineMatch::new("test reason");
        assert_eq!(m.get_reason(), "test reason");
        assert!(m.get_a_addresses().is_empty());
        assert!(m.get_b_addresses().is_empty());
    }

    #[test]
    fn test_add() {
        let mut m = SubroutineMatch::new("reason");
        assert!(m.add(addr(0x100), true));
        assert!(m.add(addr(0x200), true));
        assert!(m.add(addr(0x300), false));

        assert_eq!(m.get_a_addresses(), &[addr(0x100), addr(0x200)]);
        assert_eq!(m.get_b_addresses(), &[addr(0x300)]);
    }

    #[test]
    fn test_remove() {
        let mut m = SubroutineMatch::new("reason");
        m.add(addr(0x100), true);
        m.add(addr(0x200), true);
        m.add(addr(0x300), false);

        assert!(!m.remove(Some(addr(0x100)), true));
        assert_eq!(m.get_a_addresses(), &[addr(0x200)]);

        assert!(!m.remove(Some(addr(0x300)), false));
        assert!(m.get_b_addresses().is_empty());
    }

    #[test]
    fn test_remove_none_returns_false() {
        let mut m = SubroutineMatch::new("reason");
        m.add(addr(0x100), true);
        assert!(!m.remove(None, true));
        assert_eq!(m.get_a_addresses(), &[addr(0x100)]);
    }

    #[test]
    fn test_remove_all_matching_occurrences() {
        let mut m = SubroutineMatch::new("reason");
        m.add(addr(0x100), true);
        m.add(addr(0x200), true);
        m.add(addr(0x100), true);

        m.remove(Some(addr(0x100)), true);
        assert_eq!(m.get_a_addresses(), &[addr(0x200)]);
    }

    #[test]
    fn test_is_one_to_one() {
        let mut m = SubroutineMatch::new("reason");
        assert!(!m.is_one_to_one());
        m.add(addr(0x100), true);
        assert!(!m.is_one_to_one());
        m.add(addr(0x200), false);
        assert!(m.is_one_to_one());
        m.add(addr(0x300), false);
        assert!(!m.is_one_to_one());
    }

    #[test]
    fn test_display() {
        let mut m = SubroutineMatch::new("reason");
        m.add(addr(0x100), true);
        m.add(addr(0x200), false);
        let s = m.to_string();
        assert!(s.starts_with("reason "));
        assert!(s.contains(" --- "));
    }
}
