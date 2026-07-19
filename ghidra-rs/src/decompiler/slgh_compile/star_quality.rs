use crate::program::model::lang::sleigh::template::ConstTpl;
use crate::sleigh::grammar::Location;

/// Represents star quality metadata for a SLEIGH construct.
///
/// Mirrors `ghidra.pcodeCPort.slgh_compile.StarQuality`.
pub struct StarQuality {
    pub location: Location,
    id: Option<ConstTpl>,
    size: i32,
}

impl StarQuality {
    pub fn new(location: Location) -> Self {
        Self {
            location,
            id: None,
            size: 0,
        }
    }

    pub fn get_id(&self) -> Option<&ConstTpl> {
        self.id.as_ref()
    }

    pub fn set_id(&mut self, id: ConstTpl) {
        self.id = Some(id);
    }

    pub fn get_size(&self) -> i32 {
        self.size
    }

    pub fn set_size(&mut self, size: i32) {
        self.size = size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction() {
        let loc = Location::new("test.sleigh", 10);
        let sq = StarQuality::new(loc);

        assert!(sq.get_id().is_none());
        assert_eq!(sq.get_size(), 0);
    }

    #[test]
    fn test_set_size() {
        let loc = Location::new("test.sleigh", 20);
        let mut sq = StarQuality::new(loc);

        sq.set_size(42);
        assert_eq!(sq.get_size(), 42);
    }

    #[test]
    fn test_set_id() {
        let loc = Location::new("test.sleigh", 30);
        let mut sq = StarQuality::new(loc);

        let const_tpl = ConstTpl::new();
        sq.set_id(const_tpl);

        assert!(sq.get_id().is_some());
    }

    #[test]
    fn test_id_can_be_retrieved_after_set() {
        let loc = Location::new("test.sleigh", 40);
        let mut sq = StarQuality::new(loc);

        let const_tpl = ConstTpl::new();
        sq.set_id(const_tpl.clone());

        let retrieved = sq.get_id();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tp, const_tpl.tp);
    }

    #[test]
    fn test_multiple_modifications() {
        let loc = Location::new("test.sleigh", 50);
        let mut sq = StarQuality::new(loc);

        sq.set_size(10);
        assert_eq!(sq.get_size(), 10);

        sq.set_size(20);
        assert_eq!(sq.get_size(), 20);

        let const_tpl = ConstTpl::new();
        sq.set_id(const_tpl);
        assert!(sq.get_id().is_some());
    }
}
