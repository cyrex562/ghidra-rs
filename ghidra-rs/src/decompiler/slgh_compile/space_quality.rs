use super::SpaceClass;
use std::fmt;

/// Represents qualities/properties of an address space.
///
/// Mirrors `ghidra.pcodeCPort.slgh_compile.SpaceQuality`.
pub struct SpaceQuality {
    pub name: String,
    pub typ: SpaceClass,
    pub size: i32,
    pub wordsize: i32,
    pub isdefault: bool,
}

impl SpaceQuality {
    pub fn new(name: String) -> Self {
        Self {
            name,
            typ: SpaceClass::RamSpace,
            size: 0,
            wordsize: 1,
            isdefault: false,
        }
    }
}

impl fmt::Display for SpaceQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sq:{{{},{:?},{},{},{}}}",
            self.name, self.typ, self.size, self.wordsize, self.isdefault
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction_with_defaults() {
        let sq = SpaceQuality::new("memory".to_string());

        assert_eq!(sq.name, "memory");
        assert_eq!(sq.typ, SpaceClass::RamSpace);
        assert_eq!(sq.size, 0);
        assert_eq!(sq.wordsize, 1);
        assert!(!sq.isdefault);
    }

    #[test]
    fn test_construction_with_different_name() {
        let sq = SpaceQuality::new("registers".to_string());

        assert_eq!(sq.name, "registers");
        assert_eq!(sq.typ, SpaceClass::RamSpace);
        assert_eq!(sq.size, 0);
        assert_eq!(sq.wordsize, 1);
        assert!(!sq.isdefault);
    }

    #[test]
    fn test_display_format() {
        let sq = SpaceQuality::new("test".to_string());

        let display = sq.to_string();
        assert_eq!(display, "sq:{test,RamSpace,0,1,false}");
    }

    #[test]
    fn test_display_with_modified_fields() {
        let mut sq = SpaceQuality::new("memory".to_string());
        sq.size = 65536;
        sq.wordsize = 4;
        sq.isdefault = true;

        let display = sq.to_string();
        assert_eq!(display, "sq:{memory,RamSpace,65536,4,true}");
    }

    #[test]
    fn test_modify_space_type() {
        let mut sq = SpaceQuality::new("regs".to_string());
        sq.typ = SpaceClass::RegisterSpace;

        assert_eq!(sq.typ, SpaceClass::RegisterSpace);
        let display = sq.to_string();
        assert_eq!(display, "sq:{regs,RegisterSpace,0,1,false}");
    }

    #[test]
    fn test_fields_are_mutable() {
        let mut sq = SpaceQuality::new("stack".to_string());

        sq.name = "heap".to_string();
        sq.size = 1024;
        sq.wordsize = 8;
        sq.isdefault = true;

        assert_eq!(sq.name, "heap");
        assert_eq!(sq.size, 1024);
        assert_eq!(sq.wordsize, 8);
        assert!(sq.isdefault);
    }
}
