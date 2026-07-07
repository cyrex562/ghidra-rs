#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FgVertexType {
    Body,
    Entry,
    Exit,
    Group,
    Singleton,
}

impl FgVertexType {
    pub fn is_entry(self) -> bool {
        matches!(self, Self::Entry | Self::Singleton)
    }

    pub fn is_exit(self) -> bool {
        matches!(self, Self::Exit | Self::Singleton)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_entry() {
        assert!(FgVertexType::Entry.is_entry());
        assert!(FgVertexType::Singleton.is_entry());
        assert!(!FgVertexType::Body.is_entry());
        assert!(!FgVertexType::Exit.is_entry());
        assert!(!FgVertexType::Group.is_entry());
    }

    #[test]
    fn test_is_exit() {
        assert!(FgVertexType::Exit.is_exit());
        assert!(FgVertexType::Singleton.is_exit());
        assert!(!FgVertexType::Body.is_exit());
        assert!(!FgVertexType::Entry.is_exit());
        assert!(!FgVertexType::Group.is_exit());
    }

    #[test]
    fn test_singleton_is_both_entry_and_exit() {
        let s = FgVertexType::Singleton;
        assert!(s.is_entry());
        assert!(s.is_exit());
    }

    #[test]
    fn test_body_is_neither() {
        let b = FgVertexType::Body;
        assert!(!b.is_entry());
        assert!(!b.is_exit());
    }

    #[test]
    fn test_group_is_neither() {
        let g = FgVertexType::Group;
        assert!(!g.is_entry());
        assert!(!g.is_exit());
    }

    #[test]
    fn test_equality() {
        assert_eq!(FgVertexType::Body, FgVertexType::Body);
        assert_ne!(FgVertexType::Entry, FgVertexType::Exit);
    }

    #[test]
    fn test_copy() {
        let v = FgVertexType::Entry;
        let v2 = v;
        assert_eq!(v, v2);
    }

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", FgVertexType::Body), "Body");
        assert_eq!(format!("{:?}", FgVertexType::Entry), "Entry");
        assert_eq!(format!("{:?}", FgVertexType::Exit), "Exit");
        assert_eq!(format!("{:?}", FgVertexType::Group), "Group");
        assert_eq!(format!("{:?}", FgVertexType::Singleton), "Singleton");
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FgVertexType::Body);
        set.insert(FgVertexType::Entry);
        set.insert(FgVertexType::Exit);
        set.insert(FgVertexType::Group);
        set.insert(FgVertexType::Singleton);
        assert_eq!(set.len(), 5);
    }
}
