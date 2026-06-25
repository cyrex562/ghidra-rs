#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarnodeType {
    Register,
    Stack,
    Memory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_type_variants() {
        assert_eq!(VarnodeType::Register, VarnodeType::Register);
        assert_eq!(VarnodeType::Stack, VarnodeType::Stack);
        assert_eq!(VarnodeType::Memory, VarnodeType::Memory);
    }

    #[test]
    fn test_varnode_type_distinct() {
        assert_ne!(VarnodeType::Register, VarnodeType::Stack);
        assert_ne!(VarnodeType::Stack, VarnodeType::Memory);
        assert_ne!(VarnodeType::Memory, VarnodeType::Register);
    }

    #[test]
    fn test_varnode_type_clone() {
        let vt = VarnodeType::Register;
        let vt_cloned = vt.clone();
        assert_eq!(vt, vt_cloned);
    }

    #[test]
    fn test_varnode_type_copy() {
        let vt = VarnodeType::Stack;
        let vt_copied = vt;
        assert_eq!(vt, vt_copied);
    }

    #[test]
    fn test_varnode_type_debug() {
        let vt = VarnodeType::Memory;
        let debug_str = format!("{:?}", vt);
        assert_eq!(debug_str, "Memory");
    }

    #[test]
    fn test_varnode_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VarnodeType::Register);
        set.insert(VarnodeType::Stack);
        set.insert(VarnodeType::Memory);
        assert_eq!(set.len(), 3);
    }
}
