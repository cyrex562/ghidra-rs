/// Tracks change information on a domain object.
pub trait DomainObjectChangeSet {
    /// Returns `true` if this domain object has any pending changes.
    fn has_changes(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysChanged;
    impl DomainObjectChangeSet for AlwaysChanged {
        fn has_changes(&self) -> bool {
            true
        }
    }

    struct NeverChanged;
    impl DomainObjectChangeSet for NeverChanged {
        fn has_changes(&self) -> bool {
            false
        }
    }

    #[test]
    fn has_changes_returns_true() {
        assert!(AlwaysChanged.has_changes());
    }

    #[test]
    fn has_changes_returns_false() {
        assert!(!NeverChanged.has_changes());
    }

    #[test]
    fn trait_object_dispatch() {
        let objects: Vec<Box<dyn DomainObjectChangeSet>> = vec![
            Box::new(AlwaysChanged),
            Box::new(NeverChanged),
        ];
        assert!(objects[0].has_changes());
        assert!(!objects[1].has_changes());
    }
}
