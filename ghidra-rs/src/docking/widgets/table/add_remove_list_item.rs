use std::fmt;

/// Operation type for an [`AddRemoveListItem`].
///
/// Corresponds to `AddRemoveListItem.Type` in the Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRemoveListItemType {
    Add,
    Remove,
    Change,
}

impl fmt::Display for AddRemoveListItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddRemoveListItemType::Add => write!(f, "ADD"),
            AddRemoveListItemType::Remove => write!(f, "REMOVE"),
            AddRemoveListItemType::Change => write!(f, "CHANGE"),
        }
    }
}

/// Represents an add, remove, or change operation for one row of a table.
///
/// Corresponds to `docking.widgets.table.AddRemoveListItem`.
#[derive(Debug, Clone)]
pub struct AddRemoveListItem<T> {
    value: T,
    item_type: AddRemoveListItemType,
}

impl<T> AddRemoveListItem<T> {
    pub fn new(item_type: AddRemoveListItemType, value: T) -> Self {
        Self { item_type, value }
    }

    pub fn is_add(&self) -> bool {
        self.item_type == AddRemoveListItemType::Add
    }

    pub fn is_remove(&self) -> bool {
        self.item_type == AddRemoveListItemType::Remove
    }

    pub fn is_change(&self) -> bool {
        self.item_type == AddRemoveListItemType::Change
    }

    pub fn item_type(&self) -> AddRemoveListItemType {
        self.item_type
    }

    pub fn value(&self) -> &T {
        &self.value
    }
}

impl<T: fmt::Display> fmt::Display for AddRemoveListItem<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{\n\tvalue: {},\n\ttype: {},\n}}", self.value, self.item_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_item_predicates() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Add, 42u32);
        assert!(item.is_add());
        assert!(!item.is_remove());
        assert!(!item.is_change());
    }

    #[test]
    fn remove_item_predicates() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Remove, "hello");
        assert!(!item.is_add());
        assert!(item.is_remove());
        assert!(!item.is_change());
    }

    #[test]
    fn change_item_predicates() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Change, 0i64);
        assert!(!item.is_add());
        assert!(!item.is_remove());
        assert!(item.is_change());
    }

    #[test]
    fn item_type_accessor() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Remove, ());
        assert_eq!(item.item_type(), AddRemoveListItemType::Remove);
    }

    #[test]
    fn value_accessor() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Add, "data");
        assert_eq!(*item.value(), "data");
    }

    #[test]
    fn display_add() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Add, "row");
        let s = item.to_string();
        assert!(s.contains("value: row"));
        assert!(s.contains("type: ADD"));
    }

    #[test]
    fn display_remove() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Remove, "row");
        let s = item.to_string();
        assert!(s.contains("type: REMOVE"));
    }

    #[test]
    fn display_change() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Change, "row");
        let s = item.to_string();
        assert!(s.contains("type: CHANGE"));
    }

    #[test]
    fn clone_preserves_fields() {
        let item = AddRemoveListItem::new(AddRemoveListItemType::Add, 99u8);
        let cloned = item.clone();
        assert_eq!(cloned.item_type(), AddRemoveListItemType::Add);
        assert_eq!(*cloned.value(), 99u8);
    }

    #[test]
    fn type_display_variants() {
        assert_eq!(AddRemoveListItemType::Add.to_string(), "ADD");
        assert_eq!(AddRemoveListItemType::Remove.to_string(), "REMOVE");
        assert_eq!(AddRemoveListItemType::Change.to_string(), "CHANGE");
    }
}
