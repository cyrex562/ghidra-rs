/// Category of a PDB record: type or item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordCategory {
    Type,
    Item,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(RecordCategory::Type, RecordCategory::Item);
    }

    #[test]
    fn copy_and_clone() {
        let a = RecordCategory::Type;
        let b = a;
        assert_eq!(a, b);
        let c = RecordCategory::Item.clone();
        assert_eq!(c, RecordCategory::Item);
    }

    #[test]
    fn debug_output() {
        assert_eq!(format!("{:?}", RecordCategory::Type), "Type");
        assert_eq!(format!("{:?}", RecordCategory::Item), "Item");
    }
}
