/// Categories that a DWARF attribute id may belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFAttributeClass {
    Address,
    AddrPtr,
    Block,
    Constant,
    ExprLoc,
    Flag,
    LinePtr,
    LocList,
    LocListsPtr,
    MacPtr,
    Reference,
    RngList,
    RngListsPtr,
    String,
    StrOffsetsPtr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_distinct() {
        let variants = [
            DWARFAttributeClass::Address,
            DWARFAttributeClass::AddrPtr,
            DWARFAttributeClass::Block,
            DWARFAttributeClass::Constant,
            DWARFAttributeClass::ExprLoc,
            DWARFAttributeClass::Flag,
            DWARFAttributeClass::LinePtr,
            DWARFAttributeClass::LocList,
            DWARFAttributeClass::LocListsPtr,
            DWARFAttributeClass::MacPtr,
            DWARFAttributeClass::Reference,
            DWARFAttributeClass::RngList,
            DWARFAttributeClass::RngListsPtr,
            DWARFAttributeClass::String,
            DWARFAttributeClass::StrOffsetsPtr,
        ];
        assert_eq!(variants.len(), 15);
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let original = DWARFAttributeClass::Constant;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", DWARFAttributeClass::Address), "Address");
        assert_eq!(format!("{:?}", DWARFAttributeClass::Reference), "Reference");
        assert_eq!(format!("{:?}", DWARFAttributeClass::StrOffsetsPtr), "StrOffsetsPtr");
    }
}
