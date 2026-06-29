use std::fmt;

/// Type discriminant for a [`RepositoryChangeEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Placeholder when no real event is present (`REP_NULL_EVENT = -1`).
    Null,
    FolderCreated,
    ItemCreated,
    FolderDeleted,
    FolderMoved,
    FolderRenamed,
    ItemDeleted,
    ItemRenamed,
    ItemMoved,
    ItemChanged,
    OpenHandleCount,
}

impl EventType {
    fn display_name(self) -> Option<&'static str> {
        match self {
            EventType::Null => None,
            EventType::FolderCreated => Some("Folder Created"),
            EventType::ItemCreated => Some("Item Created"),
            EventType::FolderDeleted => Some("Folder Deleted"),
            EventType::FolderMoved => Some("Folder Moved"),
            EventType::FolderRenamed => Some("Folder Renamed"),
            EventType::ItemDeleted => Some("Item Deleted"),
            EventType::ItemRenamed => Some("Item Renamed"),
            EventType::ItemMoved => Some("Item Moved"),
            EventType::ItemChanged => Some("Item Changed"),
            EventType::OpenHandleCount => Some("Open Handle Cnt"),
        }
    }
}

/// Repository change event (used by server only).
///
/// Fields not applicable to a given [`EventType`] may be `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryChangeEvent {
    pub event_type: EventType,
    pub parent_path: Option<String>,
    pub name: Option<String>,
    pub new_parent_path: Option<String>,
    pub new_name: Option<String>,
}

impl RepositoryChangeEvent {
    /// Create a new `RepositoryChangeEvent`.
    ///
    /// Parameters not applicable to the specified `event_type` may be `None`.
    pub fn new(
        event_type: EventType,
        parent_path: Option<String>,
        name: Option<String>,
        new_parent_path: Option<String>,
        new_name: Option<String>,
    ) -> Self {
        Self {
            event_type,
            parent_path,
            name,
            new_parent_path,
            new_name,
        }
    }
}

fn display_opt(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("null")
}

impl fmt::Display for RepositoryChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.event_type.display_name() {
            Some(type_name) => write!(
                f,
                "<{},parentPath={},name={},newParentPath={},newName={}>",
                type_name,
                display_opt(&self.parent_path),
                display_opt(&self.name),
                display_opt(&self.new_parent_path),
                display_opt(&self.new_name),
            ),
            None if self.event_type == EventType::Null => write!(f, "<Null Event>"),
            None => write!(f, "<Unknown RepositoryChangeEvent>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stores_fields() {
        let ev = RepositoryChangeEvent::new(
            EventType::FolderCreated,
            Some("/parent".into()),
            Some("folder".into()),
            None,
            None,
        );
        assert_eq!(ev.event_type, EventType::FolderCreated);
        assert_eq!(ev.parent_path.as_deref(), Some("/parent"));
        assert_eq!(ev.name.as_deref(), Some("folder"));
        assert!(ev.new_parent_path.is_none());
        assert!(ev.new_name.is_none());
    }

    #[test]
    fn test_display_known_type() {
        let ev = RepositoryChangeEvent::new(
            EventType::ItemMoved,
            Some("/src".into()),
            Some("item.gdt".into()),
            Some("/dst".into()),
            Some("item_new.gdt".into()),
        );
        assert_eq!(
            ev.to_string(),
            "<Item Moved,parentPath=/src,name=item.gdt,newParentPath=/dst,newName=item_new.gdt>"
        );
    }

    #[test]
    fn test_display_null_fields_print_null() {
        let ev = RepositoryChangeEvent::new(
            EventType::FolderDeleted,
            Some("/root".into()),
            Some("sub".into()),
            None,
            None,
        );
        assert_eq!(
            ev.to_string(),
            "<Folder Deleted,parentPath=/root,name=sub,newParentPath=null,newName=null>"
        );
    }

    #[test]
    fn test_display_null_event() {
        let ev = RepositoryChangeEvent::new(EventType::Null, None, None, None, None);
        assert_eq!(ev.to_string(), "<Null Event>");
    }

    #[test]
    fn test_clone_and_eq() {
        let ev = RepositoryChangeEvent::new(
            EventType::ItemChanged,
            Some("/p".into()),
            Some("n".into()),
            None,
            None,
        );
        assert_eq!(ev.clone(), ev);
    }

    #[test]
    fn test_ne_different_type() {
        let a = RepositoryChangeEvent::new(EventType::FolderCreated, None, None, None, None);
        let b = RepositoryChangeEvent::new(EventType::FolderDeleted, None, None, None, None);
        assert_ne!(a, b);
    }

    #[test]
    fn test_all_event_types_have_display_name() {
        let named = [
            EventType::FolderCreated,
            EventType::ItemCreated,
            EventType::FolderDeleted,
            EventType::FolderMoved,
            EventType::FolderRenamed,
            EventType::ItemDeleted,
            EventType::ItemRenamed,
            EventType::ItemMoved,
            EventType::ItemChanged,
            EventType::OpenHandleCount,
        ];
        for et in named {
            assert!(
                et.display_name().is_some(),
                "{:?} should have a display name",
                et
            );
        }
        assert!(EventType::Null.display_name().is_none());
    }

    #[test]
    fn test_display_open_handle_count() {
        let ev = RepositoryChangeEvent::new(EventType::OpenHandleCount, None, None, None, None);
        assert!(ev.to_string().starts_with("<Open Handle Cnt,"));
    }

    #[test]
    fn test_debug_contains_type_name() {
        let ev = RepositoryChangeEvent::new(EventType::ItemRenamed, None, None, None, None);
        let dbg = format!("{:?}", ev);
        assert!(dbg.contains("ItemRenamed"));
        assert!(dbg.contains("RepositoryChangeEvent"));
    }
}
